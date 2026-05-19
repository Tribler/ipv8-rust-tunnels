use std::sync::atomic::{AtomicU64, Ordering};

use openssl::derive::Deriver;
use openssl::hash::MessageDigest;
use openssl::md::Md;
use openssl::pkey::{Id, PKey};
use openssl::pkey_ctx::{HkdfMode, PkeyCtx};
use openssl::sign::Signer;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::crypto::cipher::{Direction, SessionKeys};
use crate::crypto::keys::{PrivateKey, PublicKey, PyPrivateKey, PyPublicKey};

macro_rules! rotl32 {
    ($x:expr, $n:expr) => {
        ($x << $n) | ($x >> (32 - $n))
    };
}

// Port of libnacl's crypto_box_beforenm.
pub fn crypto_box_beforenm(pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, String> {
    if pk.len() != 32 || sk.len() != 32 {
        return Err("Inputs must be 32 bytes".to_string());
    }

    // Clamp sk (same as libnacl's crypto_scalarmult_curve25519)
    let mut clamped_sk = sk.to_vec();
    clamped_sk[0] &= 248;
    clamped_sk[31] &= 127;
    clamped_sk[31] |= 64;

    // X25519 DH of the clamped sk key with the peer's pk
    let s = (|| -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let openssl_sk = PKey::private_key_from_raw_bytes(&clamped_sk, Id::X25519)?;
        let openssl_pk = PKey::public_key_from_raw_bytes(pk, Id::X25519)?;
        let mut deriver = Deriver::new(&openssl_sk)?;
        deriver.set_peer(&openssl_pk)?;
        deriver.derive_to_vec()
    })()
    .map_err(|e| format!("X25519 DH failed: {}", e))?;

    // Perform hsalsa20 (same as libnacl's crypto_core_hsalsa20)
    // Using the salsa20 crate for this proved problematic.
    let load32_le = |b: &[u8], i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());

    let mut x0: u32 = 0x61707865;
    let mut x5: u32 = 0x3320646e;
    let mut x10: u32 = 0x79622d32;
    let mut x15: u32 = 0x6b206574;
    let mut x1 = load32_le(&s, 0);
    let mut x2 = load32_le(&s, 4);
    let mut x3 = load32_le(&s, 8);
    let mut x4 = load32_le(&s, 12);
    let mut x11 = load32_le(&s, 16);
    let mut x12 = load32_le(&s, 20);
    let mut x13 = load32_le(&s, 24);
    let mut x14 = load32_le(&s, 28);
    let mut x6: u32 = 0;
    let mut x7: u32 = 0;
    let mut x8: u32 = 0;
    let mut x9: u32 = 0;

    for _ in (0..20).step_by(2) {
        x4 ^= rotl32!(x0.wrapping_add(x12), 7);
        x8 ^= rotl32!(x4.wrapping_add(x0), 9);
        x12 ^= rotl32!(x8.wrapping_add(x4), 13);
        x0 ^= rotl32!(x12.wrapping_add(x8), 18);
        x9 ^= rotl32!(x5.wrapping_add(x1), 7);
        x13 ^= rotl32!(x9.wrapping_add(x5), 9);
        x1 ^= rotl32!(x13.wrapping_add(x9), 13);
        x5 ^= rotl32!(x1.wrapping_add(x13), 18);
        x14 ^= rotl32!(x10.wrapping_add(x6), 7);
        x2 ^= rotl32!(x14.wrapping_add(x10), 9);
        x6 ^= rotl32!(x2.wrapping_add(x14), 13);
        x10 ^= rotl32!(x6.wrapping_add(x2), 18);
        x3 ^= rotl32!(x15.wrapping_add(x11), 7);
        x7 ^= rotl32!(x3.wrapping_add(x15), 9);
        x11 ^= rotl32!(x7.wrapping_add(x3), 13);
        x15 ^= rotl32!(x11.wrapping_add(x7), 18);
        x1 ^= rotl32!(x0.wrapping_add(x3), 7);
        x2 ^= rotl32!(x1.wrapping_add(x0), 9);
        x3 ^= rotl32!(x2.wrapping_add(x1), 13);
        x0 ^= rotl32!(x3.wrapping_add(x2), 18);
        x6 ^= rotl32!(x5.wrapping_add(x4), 7);
        x7 ^= rotl32!(x6.wrapping_add(x5), 9);
        x4 ^= rotl32!(x7.wrapping_add(x6), 13);
        x5 ^= rotl32!(x4.wrapping_add(x7), 18);
        x11 ^= rotl32!(x10.wrapping_add(x9), 7);
        x8 ^= rotl32!(x11.wrapping_add(x10), 9);
        x9 ^= rotl32!(x8.wrapping_add(x11), 13);
        x10 ^= rotl32!(x9.wrapping_add(x8), 18);
        x12 ^= rotl32!(x15.wrapping_add(x14), 7);
        x13 ^= rotl32!(x12.wrapping_add(x15), 9);
        x14 ^= rotl32!(x13.wrapping_add(x12), 13);
        x15 ^= rotl32!(x14.wrapping_add(x13), 18);
    }

    let mut out = vec![0u8; 32];
    out[0..4].copy_from_slice(&x0.to_le_bytes());
    out[4..8].copy_from_slice(&x5.to_le_bytes());
    out[8..12].copy_from_slice(&x10.to_le_bytes());
    out[12..16].copy_from_slice(&x15.to_le_bytes());
    out[16..20].copy_from_slice(&x6.to_le_bytes());
    out[20..24].copy_from_slice(&x7.to_le_bytes());
    out[24..28].copy_from_slice(&x8.to_le_bytes());
    out[28..32].copy_from_slice(&x9.to_le_bytes());

    Ok(out)
}

impl PrivateKey {
    pub fn diffie_hellman(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, String> {
        let sk_bytes = self.crypt_sk.get().ok_or("No crypt_sk")?;

        crypto_box_beforenm(peer_public_key, sk_bytes).map_err(|e| e.to_string())
    }

    pub fn get_crypt_pk(&self) -> Result<Vec<u8>, String> {
        let sk_bytes = self.crypt_sk.get().ok_or("No crypt_sk")?;

        (|| -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let my_sk = PKey::private_key_from_raw_bytes(sk_bytes, Id::X25519)?;
            my_sk.raw_public_key()
        })()
        .map_err(|e| e.to_string())
    }
}

impl PublicKey {
    pub fn get_crypt_pk(&self) -> Result<Vec<u8>, String> {
        self.crypt_pk.clone().ok_or_else(|| "No crypt_pk".to_string())
    }
}

impl SessionKeys {
    pub fn generate_inbound(
        my_sk: &PrivateKey,
        dh_received: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, SessionKeys), String> {
        // Derives the cryptographic session keys and generates a one-time-use
        // public key to answer an inbound circuit request.
        let tmp_key = PrivateKey::generate("curve25519")
            .map_err(|e| format!("Failed to generate ephemeral key: {}", e))?;

        let dh1 = tmp_key.diffie_hellman(dh_received).map_err(|e| e.to_string())?;
        let dh2 = my_sk.diffie_hellman(dh_received).map_err(|e| e.to_string())?;
        let shared_secret = [dh1.as_slice(), dh2.as_slice()].concat();

        let crypt_pk = tmp_key.get_crypt_pk().map_err(|e| e.to_string())?;
        let auth = crypto_auth(&shared_secret[..32], &crypt_pk).map_err(|e| e.to_string())?;
        let keys = generate_session_keys(&shared_secret).map_err(|e| e.to_string())?;

        Ok((crypt_pk, auth, keys))
    }

    pub fn verify_outbound(
        dh_secret: &PrivateKey,
        crypt_pk: &[u8],
        key_data: &[u8],
        auth: &[u8],
    ) -> Result<SessionKeys, String> {
        // Verifies the remote authentication signature and derives the corresponding
        // session keys from an outbound circuit response.
        let dh1 =
            dh_secret.diffie_hellman(key_data).map_err(|e| format!("remote Ephemeral DH failure: {e}"))?;
        let dh2 =
            dh_secret.diffie_hellman(crypt_pk).map_err(|e| format!("remote Identity DH failure: {e}"))?;

        let shared_secret = [dh1.as_slice(), dh2.as_slice()].concat();

        if !crypto_auth_verify(auth, &shared_secret[..32], key_data) {
            return Err("error verifying shared secret".to_owned());
        }

        generate_session_keys(&shared_secret).map_err(|e| format!("Failed to generate session keys: {e}"))
    }
}

pub fn crypto_auth(key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let pkey = PKey::hmac(key).map_err(|e| e.to_string())?;
    let mut signer = Signer::new(MessageDigest::sha512(), &pkey).map_err(|e| e.to_string())?;

    signer.update(message).map_err(|e| e.to_string())?;
    let tag = signer.sign_to_vec().map_err(|e| e.to_string())?;

    Ok(tag[..32].to_vec())
}

pub fn crypto_auth_verify(tag: &[u8], key: &[u8], message: &[u8]) -> bool {
    if let Ok(calculated_tag) = crypto_auth(key, message) {
        return openssl::memcmp::eq(&calculated_tag, tag);
    }
    false
}

pub fn generate_session_keys(shared_secret: &[u8]) -> Result<SessionKeys, String> {
    let key = (|| -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
        ctx.derive_init()?;
        ctx.set_hkdf_mode(HkdfMode::EXPAND_ONLY)?;
        ctx.set_hkdf_key(shared_secret)?;
        ctx.set_hkdf_md(Md::sha256())?;
        ctx.add_hkdf_info(b"key_generation")?;

        let mut out = vec![0u8; 72];
        ctx.derive(Some(&mut out))?;
        Ok(out)
    })()
    .map_err(|e| e.to_string())?;

    Ok(SessionKeys {
        key_backward: key[0..32].to_vec(),
        key_forward: key[32..64].to_vec(),

        salt_backward: key[64..68].to_vec(),
        salt_forward: key[68..72].to_vec(),

        salt_explicit_backward: AtomicU64::new(1),
        salt_explicit_forward: AtomicU64::new(1),
    })
}

// PyO3 bindings

#[pyfunction(name = "crypto_box_beforenm")]
pub fn py_crypto_box_beforenm(pk: &[u8], sk: &[u8]) -> PyResult<Vec<u8>> {
    crypto_box_beforenm(pk, sk).map_err(PyValueError::new_err)
}

#[pymethods]
impl PyPrivateKey {
    fn diffie_hellman(&self, peer_public_key: &[u8]) -> PyResult<Vec<u8>> {
        self.core.diffie_hellman(peer_public_key).map_err(PyValueError::new_err)
    }

    fn get_crypt_pk(&self) -> PyResult<Vec<u8>> {
        self.core.get_crypt_pk().map_err(PyValueError::new_err)
    }
}

#[pymethods]
impl PyPublicKey {
    fn get_crypt_pk(&self) -> PyResult<Vec<u8>> {
        self.core.get_crypt_pk().map_err(PyValueError::new_err)
    }
}

#[pyfunction(name = "crypto_auth")]
pub fn py_crypto_auth(key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    crypto_auth(key, message).map_err(PyValueError::new_err)
}

#[pyfunction(name = "crypto_auth_verify")]
pub fn py_crypto_auth_verify(tag: &[u8], key: &[u8], message: &[u8]) -> bool {
    crypto_auth_verify(tag, key, message)
}

#[pyclass(name = "SessionKeys")]
#[derive(Debug)]
pub struct PySessionKeys {
    pub core: SessionKeys,
}

#[pymethods]
impl PySessionKeys {
    #[getter]
    pub fn get_key_forward(&self) -> Vec<u8> {
        self.core.key_forward.clone()
    }
    #[setter]
    pub fn set_key_forward(&mut self, val: Vec<u8>) {
        self.core.key_forward = val;
    }

    #[getter]
    pub fn get_key_backward(&self) -> Vec<u8> {
        self.core.key_backward.clone()
    }
    #[setter]
    pub fn set_key_backward(&mut self, val: Vec<u8>) {
        self.core.key_backward = val;
    }

    #[getter]
    pub fn get_salt_forward(&self) -> Vec<u8> {
        self.core.salt_forward.clone()
    }
    #[setter]
    pub fn set_salt_forward(&mut self, val: Vec<u8>) {
        self.core.salt_forward = val;
    }

    #[getter]
    pub fn get_salt_backward(&self) -> Vec<u8> {
        self.core.salt_backward.clone()
    }
    #[setter]
    pub fn set_salt_backward(&mut self, val: Vec<u8>) {
        self.core.salt_backward = val;
    }

    #[getter]
    pub fn get_salt_explicit_forward(&self) -> u64 {
        self.core.salt_explicit_forward.load(Ordering::Relaxed)
    }
    #[setter]
    pub fn set_salt_explicit_forward(&mut self, val: u64) {
        self.core.salt_explicit_forward.store(val, Ordering::Relaxed);
    }

    #[getter]
    pub fn get_salt_explicit_backward(&self) -> u64 {
        self.core.salt_explicit_backward.load(Ordering::Relaxed)
    }
    #[setter]
    pub fn set_salt_explicit_backward(&mut self, val: u64) {
        self.core.salt_explicit_backward.store(val, Ordering::Relaxed);
    }

    pub fn encrypt_str(&mut self, content: &[u8], direction: i32) -> PyResult<Vec<u8>> {
        let dir = match direction {
            0 => Direction::Forward,
            1 => Direction::Backward,
            _ => return Err(PyValueError::new_err("Invalid direction: use 0 (forward) or 1 (backward)")),
        };

        let mut buffer = content.to_vec();
        self.core.encrypt_in_place(&mut buffer, dir).map_err(PyRuntimeError::new_err)?;
        Ok(buffer)
    }

    pub fn decrypt_str(&self, content: &[u8], direction: i32) -> PyResult<Vec<u8>> {
        let dir = match direction {
            0 => Direction::Forward,
            1 => Direction::Backward,
            _ => return Err(PyValueError::new_err("Invalid direction: use 0 (forward) or 1 (backward)")),
        };

        let mut buffer = content.to_vec();
        self.core.decrypt_in_place(&mut buffer, dir).map_err(PyValueError::new_err)?;
        Ok(buffer)
    }
}

#[pyfunction(name = "generate_session_keys")]
pub fn py_generate_session_keys(shared_secret: &[u8]) -> PyResult<PySessionKeys> {
    let core = generate_session_keys(shared_secret).map_err(PyValueError::new_err)?;
    Ok(PySessionKeys { core })
}
