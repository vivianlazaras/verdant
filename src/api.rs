use crate::client::auth as client_auth;
use crate::server::auth as server_auth;
use reqwest;
use serde_json::Value;
use std::error::Error;
use crate::auth::LoginResult;
use crate::server::auth::LoginResponse;

use jsonwebtoken::DecodingKey;
use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit, generic_array::GenericArray}};
/// Simple API client for auth-related endpoints.
pub struct APIClient {
    pub url: String,
    pub decoder: DecodingKey,
}

impl APIClient {
    /// Create a new API client pointing at `url`.
    pub fn new(url: impl Into<String>, decoder: DecodingKey) -> Self {
        Self { url: url.into(), decoder }
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
        &self,
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
        let login_request = client_auth::LoginRequest {
            username: username.clone(),
            request: credential_request,
        };

        let client = reqwest::Client::new();
        let endpoint = format!("{}/login/start", self.url.trim_end_matches('/'));

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
        match initial_resp {
            LoginResponse::OTP => {
                Ok(LoginResult::PasswordReset)
            },
            LoginResponse::PAKE(cred_response) => {
                match opaque_client.finish_login(client_login, cred_response) {
                    Ok((key, finalize)) => {
                        let finalize_endpoint = format!("{}/login/finalize", self.url.trim_end_matches('/'));

                        let final_resp = client
                            .post(&finalize_endpoint)
                            .json(&finalize)
                            .send()
                            .await?
                            .error_for_status()?
                            .json::<LoginResult>()
                            .await?;

                        match final_resp {
                            LoginResult::Success(token) => {
                                Ok(LoginResult::Success(Self::validate_token(&token, &self.decoder, &key)?))
                            },
                            _ => {
                                Ok(final_resp)
                            },
                        }
                    },
                    Err(e) => {
                        Err(crate::errors::Error::Opaque(e))
                    },
                }
            },
        }

        
    }

    pub fn validate_token(
        token_enc: &str,
        decoder: &DecodingKey,
        session_key: &[u8],
    ) -> Result<String, crate::errors::Error> {
        // local imports to avoid changing top-level use list
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

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())?;

        let jwt_str = String::from_utf8(plaintext)?;

        let validation = jsonwebtoken::Validation::default();
        let token_data = jsonwebtoken::decode::<Value>(&jwt_str, decoder, &validation)?;

        Ok(jwt_str)
    }
}