use opaque_ke::{ClientLogin, CredentialRequest, ClientLoginFinishParameters, ClientRegistrationFinishParameters, RegistrationUpload, ClientRegistration, RegistrationRequest, CredentialResponse, CredentialFinalization};
use opaque_ke::errors::ProtocolError;

use serde_derive::{Serialize, Deserialize};
use crate::auth::DefaultCipherSuite;

use rand::rngs::OsRng;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginRequest {
    pub username: String,
    pub request: CredentialRequest<DefaultCipherSuite>,
}

pub struct Client {
    password: String,
}

impl Client {
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into() }
    }

    // Step 1: Registration start
    pub fn start_registration(&self) -> Result<(ClientRegistration<DefaultCipherSuite>, RegistrationRequest<DefaultCipherSuite>), ProtocolError> {
        let mut rng = OsRng;
        let start = ClientRegistration::start(&mut rng, self.password.as_bytes())?;
        Ok((start.state, start.message))
    }

    // Step 2: Finish registration using server response
    pub fn finish_registration(
        &self,
        registration: ClientRegistration<DefaultCipherSuite>,
        response: opaque_ke::RegistrationResponse<DefaultCipherSuite>,
    ) -> Result<RegistrationUpload<DefaultCipherSuite>, ProtocolError> {
        let mut rng = OsRng;
        let result = registration.finish(&mut rng, self.password.as_bytes(), response, ClientRegistrationFinishParameters::default())?;
        Ok(result.message)
    }

    // Step 3: Start login (authentication)
    pub fn start_login(&self) -> Result<(ClientLogin<DefaultCipherSuite>, opaque_ke::CredentialRequest<DefaultCipherSuite>), ProtocolError> {
        let mut rng = OsRng;
        let result = ClientLogin::<DefaultCipherSuite>::start(&mut rng, self.password.as_bytes())?;
        Ok((result.state, result.message))
    }

    // Step 4: Finish login
    pub fn finish_login(
        &self,
        client_login: ClientLogin<DefaultCipherSuite>,
        credential_response: CredentialResponse<DefaultCipherSuite>,
    ) -> Result<(Vec<u8>, CredentialFinalization<DefaultCipherSuite>), ProtocolError> {
        let result = client_login.finish(self.password.as_bytes(), credential_response, ClientLoginFinishParameters::default())?;
        Ok((result.session_key.as_slice().to_vec(), result.message))
    }
}
