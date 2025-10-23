use opaque_ke::{
    RegistrationResponse, RegistrationRequest, RegistrationUpload, ServerRegistration, ServerSetup, ServerLogin, CredentialResponse, CredentialFinalization
};

use serde_derive::{Serialize, Deserialize};

use opaque_ke::errors::ProtocolError;
use opaque_ke::ServerLoginStartParameters;

use crate::auth::DefaultCipherSuite;

use rand::rngs::OsRng;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LoginResponse {
    OTP,
    PAKE(CredentialResponse<DefaultCipherSuite>),
}

pub struct Server {
    setup: ServerSetup<DefaultCipherSuite>,
    // e.g. a database of username -> StoredUserRecord
}

impl Server {
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self {
            setup: ServerSetup::new(&mut rng),
        }
    }

    // Step 1: Handle registration request
    pub fn start_registration(
        &self,
        request: RegistrationRequest<DefaultCipherSuite>,
        username: &str,
    ) -> Result<RegistrationResponse<DefaultCipherSuite>, ProtocolError> {
        let response = ServerRegistration::start(&self.setup, request, username.as_bytes())?.message;
        Ok(response)
    }

    // Step 2: Finalize registration and store record
    pub fn finish_registration(&mut self, upload: RegistrationUpload<DefaultCipherSuite>) -> ServerRegistration<DefaultCipherSuite> {
        ServerRegistration::finish(upload)
    }

    // Step 3: Handle login start
    pub fn start_login(
        &self,
        registration: ServerRegistration<DefaultCipherSuite>,
        credential_request: opaque_ke::CredentialRequest<DefaultCipherSuite>,
        username: &str,
    ) -> Result<(ServerLogin<DefaultCipherSuite>, CredentialResponse<DefaultCipherSuite>), ProtocolError> {
        let mut rng = OsRng;
        let result = ServerLogin::start(&mut rng, &self.setup, Some(registration), credential_request, username.as_bytes(), ServerLoginStartParameters::default())?;
        Ok((result.state, result.message))
    }

    // Step 4: Finish login
    pub fn finish_login(&self, server_login: ServerLogin<DefaultCipherSuite>, client_finalization: CredentialFinalization<DefaultCipherSuite>) -> Result<Vec<u8>, ProtocolError> {
        // now both sides share a session key!
        let result = server_login.finish(client_finalization)?;
        Ok(result.session_key.as_slice().to_vec())
    }
}

