use std::fmt;
use std::sync::OnceLock;

use openssl::asn1::Asn1Object;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAnyMethods, PyInt};

fn bytes_to_py_string(bytes: &[u8]) -> String {
    let mut escaped = String::from("b\"");
    for &byte in bytes {
        for ascii_byte in std::ascii::escape_default(byte) {
            escaped.push(ascii_byte as char);
        }
    }
    escaped.push('"');
    escaped
}

#[derive(Clone)]
pub struct PublicKey {
    pub inner: PKey<Public>,
    pub crypt_pk: Option<Vec<u8>>,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.key_to_bin() {
            Ok(bytes) => {
                let mut escaped = String::from("b\"");
                for byte in bytes {
                    // Escape non-ascii (\x00, \n, etc.)
                    for ascii_byte in std::ascii::escape_default(byte) {
                        escaped.push(ascii_byte as char);
                    }
                }
                escaped.push('"');

                f.debug_struct("PublicKey").field("binary", &escaped).finish()
            }
            Err(e) => f.debug_struct("PublicKey").field("error", &e).finish(),
        }
    }
}

impl PublicKey {
    pub fn from_bytes(keystring: &[u8]) -> Result<Self, String> {
        // LibNaCLPK: 10 byte prefix + 32 byte crypt_pk + 32 byte vk
        if keystring.starts_with(b"LibNaCLPK:") && keystring.len() >= 74 {
            let crypt_pk = keystring[10..42].to_vec();
            let vk_bytes = &keystring[42..74];

            let inner = PKey::public_key_from_raw_bytes(vk_bytes, Id::ED25519)
                .map_err(|e| format!("Failed to load Ed25519 PK: {}", e))?;

            return Ok(Self { inner, crypt_pk: Some(crypt_pk) });
        }

        // OpenSSL PEM/DER
        let inner = if keystring.starts_with(b"-----") {
            PKey::public_key_from_pem(keystring)
        } else {
            PKey::public_key_from_der(keystring)
        }
        .map_err(|e| format!("Failed to load public key: {}", e))?;

        Ok(Self { inner, crypt_pk: None })
    }

    pub fn verify(&self, signature: &[u8], msg: &[u8]) -> bool {
        if self.inner.id() == Id::ED25519 {
            return Verifier::new_without_digest(&self.inner)
                .and_then(|mut verifier| verifier.verify_oneshot(signature, msg))
                .unwrap_or(false);
        }

        let mid = signature.len() / 2;
        if signature.is_empty() || signature.len() % 2 != 0 {
            return false;
        }

        let res: Result<bool, openssl::error::ErrorStack> = (|| {
            let r = BigNum::from_slice(&signature[..mid])?;
            let s = BigNum::from_slice(&signature[mid..])?;
            let sig = EcdsaSig::from_private_components(r, s)?;
            let ec = self.inner.ec_key()?;
            let digest = openssl::hash::hash(MessageDigest::sha1(), msg)?;

            Ok(sig.verify(&digest, &ec)?)
        })();

        res.unwrap_or(false)
    }

    pub fn key_to_bin(&self) -> Result<Vec<u8>, String> {
        if self.inner.id() == Id::ED25519 {
            let vk = self.inner.raw_public_key().map_err(|e| e.to_string())?;
            // Use crypt_pk if available, otherwise default to vk
            let pk = self.crypt_pk.as_ref().unwrap_or(&vk);
            return Ok([b"LibNaCLPK:".as_slice(), pk, &vk].concat());
        }
        self.inner.public_key_to_der().map_err(|e| e.to_string())
    }

    pub fn key_to_hash(&self) -> Result<[u8; 20], String> {
        let bin_key = self.key_to_bin().map_err(|e| format!("Failed to call key_to_bin: {e}"))?;
        let digest = openssl::sha::sha1(&bin_key);
        Ok(digest)
    }

    pub fn key_to_pem(&self) -> Result<Vec<u8>, String> {
        self.inner.public_key_to_pem().map_err(|e| e.to_string())
    }

    pub fn get_signature_length(&self) -> usize {
        if self.inner.id() == Id::ED25519 {
            return self.inner.size();
        }

        self.inner
            .ec_key()
            .map(|ec| {
                let bits = ec.group().degree();
                let field_len = (bits + 7) / 8;
                (field_len * 2) as usize
            })
            .unwrap_or_else(|_| self.inner.size())
    }

    pub fn curve_name(&self) -> Result<&'static str, String> {
        match self.inner.id() {
            Id::ED25519 => Ok("curve25519"),
            Id::EC => self
                .inner
                .ec_key()
                .and_then(|ec| ec.group().curve_name().ok_or_else(openssl::error::ErrorStack::get))
                .and_then(|nid| nid.short_name())
                .map_err(|e| e.to_string()),
            _ => Err("Unsupported key type".to_string()),
        }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        match (self.key_to_bin(), other.key_to_bin()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}
impl Eq for PublicKey {}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        if let Ok(bin_bytes) = self.key_to_bin() {
            bin_bytes.hash(state);
        }
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    pub inner: PKey<Private>,
    pub crypt_sk: OnceLock<Vec<u8>>,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes_res = if self.inner.id() == Id::ED25519 {
            self.inner
                .raw_private_key()
                .map(|seed| {
                    // No crypt_sk -> use 32 zero bytes
                    let fallback = vec![0u8; 32];
                    let sk = self.crypt_sk.get().unwrap_or(&fallback);
                    [b"LibNaCLSK:".as_slice(), sk, &seed].concat()
                })
                .map_err(|e| e.to_string())
        } else {
            self.inner.private_key_to_der().map_err(|e| e.to_string())
        };

        match bytes_res {
            Ok(bytes) => f.debug_struct("PrivateKey").field("binary", &bytes_to_py_string(&bytes)).finish(),
            Err(e) => f.debug_struct("PrivateKey").field("error", &e).finish(),
        }
    }
}

impl PrivateKey {
    pub fn from_bytes(keystring: &[u8]) -> Result<Self, String> {
        // LibNaCL DualSecret: LibNaCLSK: + crypt_sk (32) + signer_seed (32) = 74 bytes
        if keystring.starts_with(b"LibNaCLSK:") && keystring.len() >= 74 {
            let crypt_sk = keystring[10..42].to_vec();
            let signer_seed = &keystring[42..74];

            let inner = PKey::private_key_from_raw_bytes(signer_seed, Id::ED25519)
                .map_err(|e| format!("Failed to load Ed25519 SK: {}", e))?;

            return Ok(Self { inner, crypt_sk: OnceLock::from(crypt_sk) });
        }

        let inner = if keystring.starts_with(b"-----") {
            PKey::private_key_from_pem(keystring)
        } else {
            PKey::private_key_from_der(keystring)
        }
        .map_err(|e| format!("Failed to load private key: {}", e))?;

        Ok(Self { inner, crypt_sk: OnceLock::new() })
    }

    pub fn key_to_bin(&self) -> Result<Vec<u8>, String> {
        if self.inner.id() == Id::ED25519 {
            let seed = self.inner.raw_private_key().map_err(|e| e.to_string())?;

            // Ensure crypt_sk exists.
            let sk = self.crypt_sk.get_or_init(|| {
                PKey::generate_x25519().and_then(|k| k.raw_private_key()).unwrap_or_default()
            });

            return Ok([b"LibNaCLSK:".as_slice(), sk, &seed].concat());
        }
        self.inner.private_key_to_der().map_err(|e| e.to_string())
    }

    pub fn public_key(&self) -> Result<PublicKey, String> {
        let vk_inner = self
            .inner
            .public_key_to_der()
            .and_then(|der| PKey::public_key_from_der(&der))
            .map_err(|e| e.to_string())?;

        let crypt_pk = self.crypt_sk.get().and_then(|sk| {
            PKey::private_key_from_raw_bytes(sk, Id::X25519).and_then(|k| k.raw_public_key()).ok()
        });

        Ok(PublicKey { inner: vk_inner, crypt_pk })
    }

    pub fn key_to_pem(&self) -> Result<Vec<u8>, String> {
        if self.inner.id() == Id::ED25519 {
            return self.inner.private_key_to_pem_pkcs8().map_err(|e| e.to_string());
        }
        self.inner.ec_key().and_then(|ec| ec.private_key_to_pem()).map_err(|e| e.to_string())
    }

    pub fn signature(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        if self.inner.id() == Id::ED25519 {
            return Signer::new_without_digest(&self.inner)
                .and_then(|mut signer| signer.sign_oneshot_to_vec(msg))
                .map_err(|e| format!("Ed25519 signature failed: {}", e));
        }

        let der_sig = Signer::new(MessageDigest::sha1(), &self.inner)
            .and_then(|mut s| s.sign_oneshot_to_vec(msg))
            .map_err(|e| e.to_string())?;

        let sig = EcdsaSig::from_der(&der_sig).map_err(|e| e.to_string())?;
        let len = self.get_signature_length() / 2;
        let mut raw = vec![0u8; len * 2];

        raw[..len].copy_from_slice(&sig.r().to_vec_padded(len as i32).map_err(|e| e.to_string())?);
        raw[len..].copy_from_slice(&sig.s().to_vec_padded(len as i32).map_err(|e| e.to_string())?);

        Ok(raw)
    }

    pub fn get_signature_length(&self) -> usize {
        if self.inner.id() == Id::ED25519 {
            return self.inner.size();
        }

        self.inner
            .ec_key()
            .map(|ec| {
                let bits = ec.group().degree();
                let field_len = (bits + 7) / 8;
                (field_len * 2) as usize
            })
            .unwrap_or_else(|_| self.inner.size())
    }

    pub fn generate(curve_name: &str) -> Result<Self, String> {
        if curve_name.to_lowercase() == "curve25519" {
            let signer = PKey::generate_ed25519().map_err(|e| e.to_string())?;
            let crypt = PKey::generate_x25519().map_err(|e| e.to_string())?;
            let crypt_sk_bytes = crypt.raw_private_key().map_err(|e| e.to_string())?;

            return Ok(Self { inner: signer, crypt_sk: OnceLock::from(crypt_sk_bytes) });
        }

        let inner = (|| {
            let nid = Asn1Object::from_str(curve_name)?.nid();
            let group = EcGroup::from_curve_name(nid)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        })()
        .map_err(|e| e.to_string())?;

        Ok(Self { inner, crypt_sk: OnceLock::new() })
    }

    pub fn curve_name(&self) -> Result<&'static str, String> {
        match self.inner.id() {
            Id::ED25519 => Ok("curve25519"),
            Id::EC => self
                .inner
                .ec_key()
                .and_then(|ec| ec.group().curve_name().ok_or_else(openssl::error::ErrorStack::get))
                .and_then(|nid| nid.short_name())
                .map_err(|e| e.to_string()),
            _ => Err("Unsupported key type".to_string()),
        }
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        match (self.key_to_bin(), other.key_to_bin()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}
impl Eq for PrivateKey {}

impl std::hash::Hash for PrivateKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        if let Ok(bin_bytes) = self.key_to_bin() {
            bin_bytes.hash(state);
        }
    }
}

#[pyclass(name = "PublicKey", from_py_object)]
#[derive(Clone, Debug)]
pub struct PyPublicKey {
    pub core: PublicKey,
}

#[pymethods]
impl PyPublicKey {
    #[new]
    pub fn new(keystring: &[u8]) -> PyResult<Self> {
        let core = PublicKey::from_bytes(keystring).map_err(PyValueError::new_err)?;
        Ok(Self { core })
    }

    pub fn verify(&self, signature: &[u8], msg: &[u8]) -> bool {
        self.core.verify(signature, msg)
    }

    pub fn key_to_bin(&self) -> PyResult<Vec<u8>> {
        self.core.key_to_bin().map_err(PyValueError::new_err)
    }

    pub fn key_to_pem(&self) -> PyResult<Vec<u8>> {
        self.core.key_to_pem().map_err(PyValueError::new_err)
    }

    pub fn get_signature_length(&self) -> usize {
        self.core.get_signature_length()
    }

    pub fn curve_name(&self) -> PyResult<&'static str> {
        self.core.curve_name().map_err(PyValueError::new_err)
    }

    pub fn __repr__(&self) -> String {
        format!("{:?}", self.core)
    }

    pub fn __str__(&self) -> String {
        format!("{:?}", self.core)
    }
}

#[pyclass(name = "PrivateKey", from_py_object)]
#[derive(Clone, Debug)]
pub struct PyPrivateKey {
    pub core: PrivateKey,
}

#[pymethods]
impl PyPrivateKey {
    #[new]
    pub fn new(keystring: &[u8]) -> PyResult<Self> {
        let core = PrivateKey::from_bytes(keystring).map_err(PyValueError::new_err)?;
        Ok(Self { core })
    }

    pub fn key_to_bin(&mut self) -> PyResult<Vec<u8>> {
        self.core.key_to_bin().map_err(PyValueError::new_err)
    }

    #[pyo3(name = "pub")]
    pub fn public_key(&self) -> PyResult<PyPublicKey> {
        let core_pub = self.core.public_key().map_err(PyValueError::new_err)?;
        Ok(PyPublicKey { core: core_pub })
    }

    pub fn key_to_pem(&self) -> PyResult<Vec<u8>> {
        self.core.key_to_pem().map_err(PyValueError::new_err)
    }

    pub fn signature(&self, msg: &[u8]) -> PyResult<Vec<u8>> {
        self.core.signature(msg).map_err(PyValueError::new_err)
    }

    pub fn get_signature_length(&self) -> usize {
        self.core.get_signature_length()
    }

    #[staticmethod]
    pub fn generate(curve_name: &str) -> PyResult<Self> {
        let core = PrivateKey::generate(curve_name).map_err(PyValueError::new_err)?;
        Ok(Self { core })
    }

    pub fn curve_name(&self) -> PyResult<&'static str> {
        self.core.curve_name().map_err(PyValueError::new_err)
    }

    pub fn __repr__(&self) -> String {
        format!("{:?}", self.core)
    }

    pub fn __str__(&self) -> String {
        format!("{:?}", self.core)
    }
}

#[pyfunction]
pub fn generate_safe_prime(py: Python<'_>, bit_length: i32) -> PyResult<Py<PyAny>> {
    let mut prime = BigNum::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    prime
        .generate_prime(bit_length, true, None, None)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to generate safe prime: {}", e)))?;

    py.get_type::<PyInt>().call_method1("from_bytes", (prime.to_vec(), "big")).map(|obj| obj.into())
}

#[pyfunction]
pub fn generate_rsa_prime(py: Python<'_>, bit_length: u32) -> PyResult<Py<PyAny>> {
    let rsa =
        openssl::rsa::Rsa::generate(bit_length * 2).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let p_bytes = rsa.p().ok_or_else(|| PyRuntimeError::new_err("RSA failed"))?.to_vec();

    py.get_type::<PyInt>().call_method1("from_bytes", (p_bytes, "big")).map(|obj| obj.into())
}

#[pyfunction]
pub fn is_prime(_py: Python<'_>, number: Bound<'_, PyInt>) -> PyResult<bool> {
    // Minimum number of bytes needed
    let byte_len = (number.call_method0("bit_length")?.extract::<usize>()? + 7) / 8;
    let bytes: Vec<u8> = number.call_method1("to_bytes", (byte_len, "big"))?.extract()?;

    let bn = BigNum::from_slice(&bytes).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let mut ctx = BigNumContext::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let is_p = bn.is_prime(64, &mut ctx).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    Ok(is_p)
}
