use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use openssl::symm::{Cipher, Crypter, Mode};
use portable_atomic::AtomicU128;

use crate::util::to_hex;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Direction {
    Forward,
    Backward,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Default, Debug)]
pub struct CounterWindow {
    // First 64 bits represents the highest salt_explicit we've seen
    // The second 64 bits serves as a bitmap of which salt_explicits we've seen up to that point
    state: AtomicU128,
}

impl Clone for CounterWindow {
    fn clone(&self) -> Self {
        Self { state: AtomicU128::new(self.state.load(Ordering::Relaxed)) }
    }
}

impl CounterWindow {
    fn check_and_update(&self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }

        self.state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let highest = (current >> 64) as u64;
                let bitmap = current as u64;

                if counter > highest {
                    let diff = counter - highest;
                    let new_bitmap = if diff >= 64 { 1 } else { (bitmap << diff) | 1 };
                    Some(((counter as u128) << 64) | (new_bitmap as u128))
                } else {
                    let diff = highest - counter;
                    if diff >= 64 {
                        return None;
                    }
                    let mask = 1u64 << diff;
                    if (bitmap & mask) != 0 {
                        return None;
                    }
                    let new_bitmap = bitmap | mask;
                    Some(((highest as u128) << 64) | (new_bitmap as u128))
                }
            })
            .is_ok()
    }
}

#[derive(Default)]
pub struct SessionKeys {
    pub key_forward: Vec<u8>,
    pub key_backward: Vec<u8>,
    pub salt_forward: Vec<u8>,
    pub salt_backward: Vec<u8>,
    pub salt_explicit_forward: AtomicU64,
    pub salt_explicit_backward: AtomicU64,
    pub window_forward: CounterWindow,
    pub window_backward: CounterWindow,
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("key_forward", &to_hex(&self.key_forward))
            .field("key_backward", &to_hex(&self.key_backward))
            .field("salt_forward", &to_hex(&self.salt_forward))
            .field("salt_backward", &to_hex(&self.salt_backward))
            .field("salt_explicit_forward", &self.salt_explicit_forward.load(Ordering::Relaxed))
            .field("salt_explicit_backward", &self.salt_explicit_backward.load(Ordering::Relaxed))
            .finish()
    }
}

impl Clone for SessionKeys {
    fn clone(&self) -> Self {
        Self {
            key_forward: self.key_forward.clone(),
            key_backward: self.key_backward.clone(),
            salt_forward: self.salt_forward.clone(),
            salt_backward: self.salt_backward.clone(),
            salt_explicit_forward: AtomicU64::new(self.salt_explicit_forward.load(Ordering::Relaxed)),
            salt_explicit_backward: AtomicU64::new(self.salt_explicit_backward.load(Ordering::Relaxed)),
            window_forward: self.window_forward.clone(),
            window_backward: self.window_backward.clone(),
        }
    }
}

impl SessionKeys {
    pub fn decrypt_in_place(&self, raw_buffer: &mut Vec<u8>, direction: Direction) -> Result<(), String> {
        let total_len = raw_buffer.len();
        if total_len < 24 {
            return Err("Content too short".to_string());
        }

        let (key, salt, window) = match direction {
            Direction::Forward => (&self.key_forward, &self.salt_forward, &self.window_forward),
            Direction::Backward => (&self.key_backward, &self.salt_backward, &self.window_backward),
        };

        // Create the 12-byte Chacha20-Poly1305 nonce (salt + counter)
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&raw_buffer[..8]);
        let counter = u64::from_be_bytes(counter_bytes);

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(salt);
        nonce[4..12].copy_from_slice(&raw_buffer[..8]);

        let ciphertext_len = total_len - 8 - 16;
        let tag_offset = total_len - 16;

        let mut crypter = Crypter::new(Cipher::chacha20_poly1305(), Mode::Decrypt, key, Some(&nonce))
            .map_err(|e| e.to_string())?;

        let tag = &raw_buffer[tag_offset..];
        crypter.set_tag(tag).map_err(|e| e.to_string())?;

        let mut bytes_written;
        unsafe {
            let cipher_part = std::slice::from_raw_parts(raw_buffer[8..].as_ptr(), ciphertext_len);

            let remaining_capacity = raw_buffer.capacity() - 8;
            let out_part = std::slice::from_raw_parts_mut(raw_buffer[8..].as_mut_ptr(), remaining_capacity);

            bytes_written =
                crypter.update(cipher_part, out_part).map_err(|e| format!("Decrypt update failed: {}", e))?;

            bytes_written += crypter
                .finalize(&mut out_part[bytes_written..])
                .map_err(|_| "AEAD integrity check failed".to_string())?;

            if !window.check_and_update(counter) {
                return Err("Replay/old packet detected".to_string());
            }

            raw_buffer.set_len(8 + bytes_written);
        }

        raw_buffer.drain(0..8);
        Ok(())
    }

    pub fn encrypt_in_place(&self, raw_buffer: &mut Vec<u8>, direction: Direction) -> Result<(), String> {
        let plaintext_len = raw_buffer.len();

        let (key, salt, counter) = match direction {
            Direction::Forward => {
                let ctr = self.salt_explicit_forward.fetch_add(1, Ordering::Relaxed) + 1;
                (&self.key_forward, &self.salt_forward, ctr)
            }
            Direction::Backward => {
                let ctr = self.salt_explicit_backward.fetch_add(1, Ordering::Relaxed) + 1;
                (&self.key_backward, &self.salt_backward, ctr)
            }
        };

        let counter_bytes = counter.to_be_bytes();

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(salt);
        nonce[4..12].copy_from_slice(&counter_bytes);

        // Format: [8-Byte Counter] + [Ciphertext Payload] + [16-Byte Auth Tag]
        let final_needed_size = 8 + plaintext_len + 16;
        raw_buffer.resize(final_needed_size, 0);
        raw_buffer.copy_within(0..plaintext_len, 8);
        raw_buffer[..8].copy_from_slice(&counter_bytes);

        let mut crypter = Crypter::new(Cipher::chacha20_poly1305(), Mode::Encrypt, key, Some(&nonce))
            .map_err(|e| e.to_string())?;

        let mut bytes_written;
        unsafe {
            let src_part = std::slice::from_raw_parts(raw_buffer[8..].as_ptr(), plaintext_len);

            let remaining_capacity = raw_buffer.capacity() - 8;
            let out_part = std::slice::from_raw_parts_mut(raw_buffer[8..].as_mut_ptr(), remaining_capacity);

            bytes_written =
                crypter.update(src_part, out_part).map_err(|e| format!("Encrypt update failed: {}", e))?;

            bytes_written += crypter
                .finalize(&mut out_part[bytes_written..])
                .map_err(|e| format!("Encrypt finalization failed: {}", e))?;

            // Calculate and add the 16-byte Poly1305 authentication tag
            let mut tag = [0u8; 16];
            crypter.get_tag(&mut tag).map_err(|e| e.to_string())?;
            raw_buffer[(8 + bytes_written)..(8 + bytes_written + 16)].copy_from_slice(&tag);
        }

        Ok(())
    }
}
