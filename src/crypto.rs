use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Error, Key, Nonce,
};

#[derive(Debug)]
pub struct SessionKeys {
    pub key_forward: Vec<u8>,
    pub key_backward: Vec<u8>,
    pub salt_forward: Vec<u8>,
    pub salt_backward: Vec<u8>,
    pub salt_explicit_forward: u32,
    pub salt_explicit_backward: u32,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Direction {
    Forward,
    Backward,
}

pub fn encrypt_str(
    content: Vec<u8>,
    keys: &mut SessionKeys,
    direction: Direction,
) -> Result<Vec<u8>, Error> {
    if direction == Direction::Forward {
        keys.salt_explicit_forward += 1;
    } else {
        keys.salt_explicit_backward += 1;
    }

    let fw = direction == Direction::Forward;
    let key = if fw { &keys.key_forward } else { &keys.key_backward };
    let salt = if fw { &keys.salt_forward } else { &keys.salt_backward };
    let salt_explicit = if fw { keys.salt_explicit_forward } else { keys.salt_explicit_backward };
    let salt_explicit_u64 = salt_explicit as u64;

    let mut nonce: Vec<u8> = salt.clone();
    nonce.append(&mut salt_explicit_u64.to_be_bytes().to_vec());

    let key = Key::from_slice(&key);
    let nonce = Nonce::from_slice(&nonce);
    let cipher = ChaCha20Poly1305::new(&key);
    let mut ciphertext = cipher.encrypt(&nonce, content.as_ref())?;

    let mut result = salt_explicit_u64.to_be_bytes().to_vec();
    result.append(&mut ciphertext);
    return Ok(result);
}

pub fn decrypt_str(
    content: Vec<u8>,
    keys: &SessionKeys,
    direction: Direction,
) -> Result<Vec<u8>, Error> {
    if content.len() < 24 {
        error!("Truncated content, got length {:?}", content.len());
        return Err(Error);
    }

    let cypher_text = &content[8..];

    let fw = direction == Direction::Forward;
    let key = if fw { &keys.key_forward } else { &keys.key_backward };
    let salt = if fw { &keys.salt_forward } else { &keys.salt_backward };

    let mut nonce = salt.clone();
    nonce.append(&mut (&content[0..8]).to_vec());

    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce);
    let plaintext = cipher.decrypt(&nonce, cypher_text.as_ref())?;
    return Ok(plaintext);
}
