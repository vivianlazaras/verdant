/// Module for cryptography utility functions.
///
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

pub fn generate_rsa_pkcs8_pair() -> (String, String) {
    // Generate a 2048-bit RSA private key
    let mut rng = OsRng;

    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");

    // Convert to PKCS#8 PEM
    let private_key_pem = private_key
        .to_pkcs8_pem(Default::default())
        .expect("failed to encode private key");

    // Extract public key and encode as PEM
    let public_key = private_key.to_public_key();
    let public_key_pem = public_key
        .to_public_key_pem(Default::default())
        .expect("failed to encode public key");

    (private_key_pem.to_string(), public_key_pem)
}

/// Compute the SHA-256 hash of `input` and return it as a lowercase hex string.
///
/// This is a **fast** cryptographic hash suitable for checksums, content-addressing,
/// or inputs to signatures. **Do not** use SHA-256 alone for password hashing.
///
/// # Example
///
/// ```ignore
/// let base64 = protocol::crypto::sha256_base64("hello");
/// assert_eq!(base64.len(), 44);
/// ```
pub fn sha256_base64(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    base64::encode(result)
}
