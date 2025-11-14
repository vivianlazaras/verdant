use crate::auth::LoginResult;
use crate::client::auth::LoginRequest;
use crate::server::auth::CredentialFinalization;
use crate::server::auth::LoginResponse;
use serde_derive::{Deserialize, Serialize};
use uuid::Uuid;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use std::str::FromStr;

type HmacSha256 = Hmac<Sha256>;

/// Represents the client's final message in the authenticated login flow.
///
/// This structure is sent **after** the OPAQUE-style password-authenticated
/// key exchange has derived a shared `session_key`.
///
/// It includes:
/// - The client's OPAQUE credential finalization message.
/// - A deterministic `client_tag` (HMAC) proving that the client possesses
///   the correct session key derived from the exchange.
///
/// The `client_tag` is computed over the transcript of all prior messages
/// (request + response) to prevent replay or mix-up attacks.
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginUpload {
    /// Unique identifier for the session, issued by the server.
    pub id: Uuid,
    /// The OPAQUE credential finalization message from the client.
    upload: CredentialFinalization,
    /// HMAC tag computed over the transcript and label `"client"`,
    /// confirming possession of the session key.
    client_tag: [u8; 32],
}

impl LoginUpload {
    /// Constructs a new `LoginUpload` message after deriving the shared session key.
    ///
    /// # Parameters
    /// - `id`: Session identifier (UUID) provided by the server.
    /// - `upload`: The OPAQUE `CredentialFinalization` message.
    /// - `session_key`: The shared session key (`K_session`) derived from OPAQUE.
    /// - `request`: The original `LoginRequest` sent by the client.
    /// - `response`: The `LoginResponse` sent by the server.
    ///
    /// # Returns
    /// A `LoginUpload` containing the client’s final message and HMAC confirmation tag.
    ///
    /// # Security
    /// The HMAC is computed as:
    /// `HMAC(K_confirm, transcript || "client")`
    /// where `K_confirm` = HKDF(K_session, "confirmation").
    pub fn new(
        id: Uuid,
        upload: CredentialFinalization,
        session_key: &[u8],
        request: &LoginRequest,
        response: &LoginResponse,
    ) -> Self {
        let k_confirm = derive_k_confirm(session_key);
        let transcript = Transcript::compute_transcript(request, response);

        // Client HMAC binds the transcript and "client" label
        let mut data = transcript.into_inner().clone();
        data.extend_from_slice(b"client");

        let client_tag = compute_hmac(&k_confirm, data);

        Self {
            id,
            upload,
            client_tag,
        }
    }

    /// Verifies the client’s confirmation tag using the provided session key
    /// and transcript messages.
    ///
    /// Returns `true` if the tag matches, meaning the client and server
    /// derived the same session key.
    pub fn verify(
        &self,
        session_key: &[u8],
        request: &LoginRequest,
        response: &LoginResponse,
    ) -> bool {
        let transcript = Transcript::compute_transcript(request, response);

        self.verify_transcript(session_key, &transcript)
    }

    /// Verifies the tag using a precomputed [`Transcript`]
    pub fn verify_transcript(&self, session_key: &[u8], transcript: &Transcript) -> bool {
        let k_confirm = derive_k_confirm(session_key);

        let mut data = transcript.clone().into_inner();
        data.extend_from_slice(b"client");

        let expected = compute_hmac(&k_confirm, data);
        expected == self.client_tag
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn finalization(&self) -> CredentialFinalization {
        self.upload.clone()
    }
}

/// Represents the server's final message in the login exchange.
///
/// This is sent after the client’s `LoginUpload` is validated and
/// confirms that the server also derived the same session key.
///
/// The `server_tag` HMAC authenticates both the transcript and
/// the server’s role in the exchange, mirroring the client-side confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCompletion {
    /// The final result of the login attempt (e.g. success or failure).
    pub result: LoginResult,
    /// HMAC tag computed over the transcript and `"server"` label,
    /// confirming the server’s possession of the session key.
    server_tag: [u8; 32],
}

impl LoginCompletion {
    pub fn unauthorized() -> Self {
        Self {
            result: LoginResult::Unauthorized,
            server_tag: [0u8; 32],
        }
    }
    /// Constructs a new `LoginCompletion` message.
    ///
    /// # Parameters
    /// - `result`: The outcome of the login attempt.
    /// - `session_key`: The shared session key derived from the OPAQUE exchange.
    /// - `request`: Original login request.
    /// - `response`: Server’s initial response message.
    ///
    /// # Security
    /// The HMAC is computed as:
    /// `HMAC(K_confirm, transcript || "server")`
    pub fn new(result: LoginResult, session_key: &[u8], transcript: Transcript) -> Self {
        let k_confirm = derive_k_confirm(session_key);

        // Server HMAC binds the same transcript and "server" label
        let mut data = transcript.clone().into_inner();
        data.extend_from_slice(b"server");

        let server_tag = compute_hmac(&k_confirm, data);

        Self { result, server_tag }
    }

    /// Verifies the server’s confirmation tag.
    ///
    /// Returns `true` if both sides derived the same session key and
    /// the transcript matches.
    pub fn verify(
        &self,
        session_key: &[u8],
        request: &LoginRequest,
        response: &LoginResponse,
    ) -> bool {
        let transcript = Transcript::compute_transcript(request, response);
        self.transcript_verify(session_key, &transcript)
    }

    /// Verifies the tag using a precomputed [`Transcript`]
    pub fn transcript_verify(&self, session_key: &[u8], transcript: &Transcript) -> bool {
        let k_confirm = derive_k_confirm(session_key);
        let mut data = transcript.clone().into_inner();
        data.extend_from_slice(b"server");

        let expected = compute_hmac(&k_confirm, data);
        expected == self.server_tag
    }
}

/// Derives a confirmation key `K_confirm` from the session key `K_session`.
///
/// This key is used exclusively for producing confirmation HMACs that
/// authenticate the handshake transcript (not for encryption or application data).
///
/// # Security
/// Uses [HKDF](https://datatracker.ietf.org/doc/html/rfc5869) with SHA-256
/// to expand the session key with the context string `"confirmation"`.
pub(crate) fn derive_k_confirm(k_session: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, k_session);
    let mut okm = [0u8; 32];
    hk.expand(b"confirmation", &mut okm).expect("HKDF expand");
    okm
}

/// Computes an HMAC-SHA256 over arbitrary data using the provided key.
///
/// This is used for confirmation tagging of transcripts and role labels.
fn compute_hmac(k_confirm: &[u8], data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(k_confirm).expect("hmac key");
    mac.update(data.as_ref());
    let result = mac.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&result.into_bytes());
    tag
}

#[derive(
    Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq, Hash,
)]
pub struct Transcript {
    pub(crate) transcript: Vec<u8>,
}

impl Transcript {
    /// Computes a deterministic binary transcript over the login request and response.
    ///
    /// The transcript is serialized using `bincode` for compact, stable encoding
    /// and prefixed with a fixed domain separator (`"LOGIN_TRANSCRIPT_V1"`) to
    /// prevent cross-protocol collisions.
    ///
    /// # Returns
    /// A concatenated byte vector:
    /// ```text
    /// LOGIN_TRANSCRIPT_V1 || bincode(LoginRequest) || bincode(LoginResponse)
    /// ```
    ///
    /// # Purpose
    /// This transcript ensures both sides are confirming *the same exchange context*,
    /// protecting against message substitution, reordering, or replay attacks.
    pub fn compute_transcript(request: &LoginRequest, response: &LoginResponse) -> Self {
        let mut transcript = Vec::new();

        // Serialize deterministically
        let req_bytes = bincode::encode_to_vec(request, bincode::config::standard())
            .expect("Failed to serialize request");
        let res_bytes = bincode::serde::encode_to_vec(response, bincode::config::standard())
            .expect("Failed to serialize response");

        transcript.extend_from_slice(b"LOGIN_TRANSCRIPT_V1");
        transcript.extend_from_slice(&req_bytes);
        transcript.extend_from_slice(&res_bytes);

        Self { transcript }
    }

    pub fn decode(val: impl Into<String>) -> Result<Self, crate::errors::Error> {
        let value = val.into();
        Ok(Transcript::from_str(&value)?)
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.transcript
    }

    pub fn new(data: Vec<u8>) -> Self {
        Self { transcript: data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.transcript
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.transcript
    }

    pub fn append(&mut self, data: &[u8]) {
        self.transcript.extend_from_slice(data);
    }
}

impl fmt::Display for Transcript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", STANDARD.encode(&self.transcript))
    }
}

impl FromStr for Transcript {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        STANDARD.decode(s).map(|bytes| Self { transcript: bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;
    use rand::{RngCore, rngs::OsRng};
    use serde_json;
    use std::str::FromStr;
    use uuid::Uuid;

    fn random_session_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn transcript_base64_roundtrip() {
        let data = b"test transcript data".to_vec();
        let t = Transcript::new(data.clone());

        let encoded = t.to_string();
        let decoded: Transcript = encoded.parse().unwrap();

        assert_eq!(t, decoded);
        assert_eq!(decoded.as_bytes(), data.as_slice());
    }

    #[test]
    fn transcript_bincode_roundtrip() {
        let data = vec![1u8, 2, 3, 4, 5, 6];
        let original = Transcript::new(data.clone());

        let encoded = bincode::encode_to_vec(&original, bincode::config::standard()).unwrap();
        let (decoded, _) =
            bincode::decode_from_slice::<Transcript, bincode::config::Configuration>(
                &encoded,
                bincode::config::standard(),
            )
            .unwrap();

        assert_eq!(original, decoded);
        assert_eq!(decoded.as_bytes(), data.as_slice());
    }
}
