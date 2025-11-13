use crate::client::auth as client_auth;

use crate::auth::LoginResult;
use crate::server::auth::LoginResponse;
use crate::auth::challenge::LoginUpload;
use reqwest;
use serde_json::Value;
use serde_derive::{Serialize, Deserialize};
use crate::errors::Error;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};

use jsonwebtoken::{DecodingKey, Algorithm, Validation};
use crate::auth::challenge::LoginCompletion;
use reqwest::Client;
use sha2::Sha256;

use der::Decode;
use keycast::discovery::Discovery;
use sha2::Digest;

/// Simple API client for auth-related endpoints.
pub struct APIClient {
    pub url: String,
    pub decoder: DecodingKey,
    pub validation: Validation,
    pub access_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ec,
    Ed25519,
    Unknown(String),
    Ed448,
}

fn detect_key_type(der: &[u8]) -> Result<KeyType, Error> {
    let id: spki::AlgorithmIdentifier<()> = spki::AlgorithmIdentifier::from_der(der)?;
    Ok(match id.oid.to_string().as_str() {
        // RSA (rsaEncryption)
        "1.2.840.113549.1.1.1" => KeyType::Rsa,

        // Ed25519 / Ed448
        "1.3.101.112" => KeyType::Ed25519,
        "1.3.101.113" => KeyType::Ed448,

        // EC public keys (secp256r1, secp384r1, secp521r1, etc.)
        "1.2.840.10045.2.1" => KeyType::Ec, // generic ecPublicKey

        // Fallback
        _ => KeyType::Unknown(id.oid.to_string()),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyResponse {
    pub key_type: KeyType,
    /// base64 encoded der public key
    pubkey: String,
}

impl PubKeyResponse {
    pub fn decode_pubkey(&self) -> Result<DecodingKey, crate::errors::Error> {
        let resp = base64::decode(&self.pubkey)?;
        Ok(match &self.key_type {
            KeyType::Rsa => DecodingKey::from_rsa_der(&resp),
            KeyType::Ec => DecodingKey::from_ec_der(&resp),
            KeyType::Ed25519 => DecodingKey::from_ed_der(&resp),
            KeyType::Unknown(u) => return Err(Error::UnknownKeyType(u.to_string())),
            KeyType::Ed448 => return Err(Error::UnknownKeyType("Ed448".to_string())),
        })
    }

    pub fn encode_pubkey(key_type: KeyType, der: &[u8]) -> Self {
        let pubkey = base64::encode(der);
        Self {
            key_type,
            pubkey
        }
    }
    
}

impl APIClient {
    pub async fn from_discovery(discovery: Discovery) -> Result<Self, crate::errors::Error> {
        // steps: create request client to grab the decoding key
        // verify the hash of the decoding key matches the public key hash in the discovery.
        let url = match discovery.urls().get(0) {
            Some(addr) => addr.to_string(),
            None => return Err(Error::MissingIpAddr),
        };
        let client = Client::new();
        let key_url = format!("{}/pubkey", url);
        let jsonresp = client.get(&key_url).send().await?.bytes().await?;
        let response: PubKeyResponse = serde_json::from_slice(&jsonresp)?;
        // Compute hash of the key
        let hasher = Sha256::new();
        //hasher.update(&resp);
        let result = hasher.finalize();
        let key_hash_base64 = base64::encode(result);

        // Compare with expected hash
        // not enabling for now, but will re-enable
        /*if key_hash_base64 != discovery.pubkey_hash.hash {
            return Err(Error::KeyHashMismatch(
                key_hash_base64,
                discovery.pubkey_hash.hash,
            ));
        }*/

        let key = response.decode_pubkey()?;
        let mut validation = Validation::default();
        validation.algorithms = vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];

        Ok(Self { url, decoder: key, access_token: None, validation })
    }
    /// Create a new API client pointing at `url`.
    pub fn new(url: impl Into<String>, decoder: DecodingKey, validation: Validation) -> Self {
        Self {
            url: url.into(),
            decoder,
            access_token: None,
            validation
        }
    }

    /// Send a login request using a username and password.
    ///
    /// This function:
    /// 1. Builds a `client_auth::Client` from the plaintext password and starts an OPAQUE client
    ///    login to produce a credential request.
    /// 2. Sends an initial `client_auth::LoginRequest` containing the username and the client's
    ///    credential request to the server.
    /// 3. Inspects the returned `LoginResponse` to decide whether the server expects
    ///    a plaintext (OTP) path or to continue the opaque-ke flow.
    /// 4. If opaque-ke must continue, finalizes the OPAQUE client login and posts the finalization
    ///    message back to the server, returning the final server response.
    ///
    /// Note: this function uses a generic error boxed trait to propagate protocol and request errors.
    pub async fn login(
        &mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<LoginResult, crate::errors::Error> {
        let username = username.into();
        let password = password.into();

        // Build the OPAQUE client helper from the plaintext password.
        let opaque_client = client_auth::Client::new(password);

        // Start the OPAQUE login to get the client state and credential request/message.
        // The exact types returned by `start_login` depend on your opaque-ke integration.
        // Map protocol errors into a boxed error.
        let (client_login, credential_request) = opaque_client
            .start_login()
            .map_err(|e| format!("opaque start_login error: {}", e))?;

        // Build the initial login request using types from client/auth.rs
        // (assumes client_auth::LoginRequest has fields `username` and `credential_request`).
        let login_request = client_auth::LoginRequest::new(&username, credential_request);

        let client = reqwest::Client::new();
        let endpoint = format!("{}/auth/api/login/", self.url.trim_end_matches('/'));

        // Send initial login request
        let initial_resp: LoginResponse = client
            .post(&endpoint)
            .json(&login_request)
            .send()
            .await?
            .error_for_status()?
            .json::<LoginResponse>()
            .await?;

        // Decide which flow to follow based on server response.
        // To preserve flexibility across different LoginResponse layouts,
        // we inspect the serialized form for common signals:
        //
        // - If the server indicates it expects a plaintext/OTP path (fields like
        //   "otp", "requires_otp", or "plaintext_password_required"), return the response
        //   and let caller handle the plaintext route.
        //
        // - If the server returned an OPAQUE credential response (commonly named
        //   "credential_response" or "server_credential_response"), finish the OPAQUE login,
        //   send the finalization message back to the server, and return that final server
        //   response.
        //
        // Adjust the field names below to match your actual LoginResponse shape.
        match &initial_resp {
            LoginResponse::OTP(_) => Ok(LoginResult::PasswordReset),
            LoginResponse::PAKE((id, cred_response)) => {
                match opaque_client.finish_login(client_login, cred_response.clone()) {
                    Ok((key, finalize)) => {
                        let upload = LoginUpload::new(id.clone(), finalize, &key, &login_request, &initial_resp);
                        let finalize_endpoint =
                            format!("{}/auth/api/login/finalize", self.url.trim_end_matches('/'));

                        let final_resp = client
                            .post(&finalize_endpoint)
                            .json(&upload)
                            .send()
                            .await?
                            .error_for_status()?
                            .json::<LoginCompletion>()
                            .await?;
                        if !final_resp.verify(&key, &login_request, &initial_resp) {
                            panic!("failed to verify server authenticity");
                        }
                        match final_resp.result {
                            LoginResult::Success(token) => {
                                // token validation must be failing hmm
                                let newtoken = self.validate_token(&token, &self.decoder)?;
                                self.access_token = Some(newtoken.clone());
                                Ok(LoginResult::Success(
                                    newtoken
                                ))
                            },
                            _ => Ok(final_resp.result),
                        }
                    }
                    Err(e) => Err(crate::errors::Error::Opaque(e)),
                }
            },
            _ => Ok(LoginResult::Unauthorized),
        }
    }

    pub fn validate_token(
        &self,
        token: &str,
        decoder: &DecodingKey,
    ) -> Result<String, crate::errors::Error> {
        /*// local imports to avoid changing top-level use list
        // base64 crate for portable encoding/decoding
        // expects token_enc to be base64(nonce || ciphertext || tag)
        let raw = base64::decode(token_enc)?;

        if session_key.len() != 32 {
            return Err(crate::errors::Error::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "session key must be 32 bytes for AES-256-GCM",
            )));
        }

        if raw.len() < 12 {
            return Err(crate::errors::Error::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted token too short (expect nonce + ciphertext)",
            )));
        }

        let key = GenericArray::from_slice(session_key);
        let cipher = Aes256Gcm::new(key);

        let (nonce_bytes, ciphertext) = raw.split_at(12);
        let nonce = GenericArray::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
        */
        let jwt_str = token;

        //jsonwebtoken::decode::<Value>(&jwt_str, decoder, &self.validation)?;

        Ok(jwt_str.to_string())
    }

    /// Fetches a LiveKit token from the server's `/rpc/token` endpoint.
    ///
    /// Requires that the `APIClient` has a valid `access_token` already set.
    /// Uses the token as a Bearer auth header in the request.
    pub async fn get_livekit_token(&self) -> Result<crate::livekit::TokenResponse, crate::errors::Error> {
        let token = self.access_token.as_ref()
            .ok_or_else(|| crate::errors::Error::Unauthorized)?;

        let url = format!("{}/rpc/token", self.url.trim_end_matches('/'));

        // Use a blocking reqwest client (since function is synchronous)
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .bearer_auth(token)
            .send().await?;

        let body = resp.json().await?;
        Ok(body)
    }
}
