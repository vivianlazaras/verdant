use opaque_ke::{RegistrationRequest, RegistrationResponse, RegistrationUpload};

pub type ServerSetup = opaque_ke::ServerSetup<DefaultCipherSuite>;
pub type ServerLogin = opaque_ke::ServerLogin<DefaultCipherSuite>;
pub type CredentialRequest = opaque_ke::CredentialRequest<DefaultCipherSuite>;
pub type CredentialResponse = opaque_ke::CredentialResponse<DefaultCipherSuite>;
pub type ServerRegistration = opaque_ke::ServerRegistration<DefaultCipherSuite>;
pub type CredentialFinalization = opaque_ke::CredentialFinalization<DefaultCipherSuite>;

use serde_derive::{Deserialize, Serialize};

use crate::auth::DefaultCipherSuite;
use opaque_ke::ServerLoginStartParameters;
use opaque_ke::errors::ProtocolError;
use uuid::Uuid;

use rand::rngs::OsRng;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LoginResponse {
    OTP(String),
    /// used for opaque login, a UUID to identify the session, and a credential response.
    PAKE((Uuid, CredentialResponse)),
    AccessDenied,
}

pub struct Server {
    setup: ServerSetup,
    // e.g. a database of username -> StoredUserRecord
}

impl Server {
    pub fn new(setup: ServerSetup) -> Self {
        let mut rng = OsRng;
        Self { setup }
    }

    // Step 1: Handle registration request
    pub fn start_registration(
        &self,
        request: RegistrationRequest<DefaultCipherSuite>,
        username: impl Into<String>,
    ) -> Result<RegistrationResponse<DefaultCipherSuite>, ProtocolError> {
        let username = username.into();
        let response =
            ServerRegistration::start(&self.setup, request, username.as_bytes())?.message;
        Ok(response)
    }

    // Step 2: Finalize registration and store record
    pub fn finish_registration(
        &self,
        upload: RegistrationUpload<DefaultCipherSuite>,
    ) -> ServerRegistration {
        ServerRegistration::finish(upload)
    }

    // Step 3: Handle login start
    pub fn start_login(
        &self,
        registration: ServerRegistration,
        credential_request: CredentialRequest,
        username: &str,
    ) -> Result<(ServerLogin, CredentialResponse), ProtocolError> {
        let mut rng = OsRng;
        let result = ServerLogin::start(
            &mut rng,
            &self.setup,
            Some(registration),
            credential_request,
            username.as_bytes(),
            ServerLoginStartParameters::default(),
        )?;
        Ok((result.state, result.message))
    }

    // Step 4: Finish login
    pub fn finish_login(
        &self,
        server_login: ServerLogin,
        client_finalization: CredentialFinalization,
    ) -> Result<Vec<u8>, ProtocolError> {
        // now both sides share a session key!
        let result = server_login.finish(client_finalization)?;
        Ok(result.session_key.as_slice().to_vec())
    }
}
