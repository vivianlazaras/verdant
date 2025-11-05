use std::string::FromUtf8Error;
use thiserror::Error;
/// Common result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
pub type ProtocolError = opaque_ke::errors::ProtocolError;

/// Error type that unifies opaque-ke protocol errors and reqwest HTTP errors.
#[derive(Debug, Error)]
pub enum Error {
    /// Errors produced by the opaque-ke protocol implementation.
    #[error("OPAQUE protocol error: {0}")]
    Opaque(#[from] opaque_ke::errors::ProtocolError),

    /// Errors produced by reqwest HTTP client.
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    /// Fallback catch-all with a human readable message.
    #[error("internal error: {0}")]
    Internal(String),

    #[error("JSONWebToken error: {0}")]
    JSONWebToken(#[from] jsonwebtoken::errors::Error),

    #[error("FromUtf8Error: {0}")]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("aes_gcm error: {0}")]
    AesGcmError(#[from] aes_gcm::Error),

    #[error("couldn't get IP Address")]
    MissingIpAddr,
    #[error("hash mismatch: {0} {1}")]
    KeyHashMismatch(String, String),
    #[error("unknown key type: {0}")]
    UnknownKeyType(String),
    #[error("SubjectPublicKeyInfo error: {0}")]
    SPKI(#[from] spki::Error),
    #[error("der Error: {0}")]
    DerError(#[from] der::Error),
    #[error("json decoding error: {0}")]
    JsonErr(#[from] serde_json::Error)
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Internal(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Internal(s)
    }
}
