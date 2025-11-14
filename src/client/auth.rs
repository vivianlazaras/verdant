use opaque_ke::errors::ProtocolError;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationUpload,
};
use uuid::Uuid;

use crate::auth::DefaultCipherSuite;
use serde_derive::{Deserialize, Serialize};

use rand::rngs::OsRng;

#[derive(bincode::Encode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub username: String,
    pub credentials: String,
}

impl LoginRequest {
    pub fn new(
        username: impl Into<String>,
        credentials: CredentialRequest<DefaultCipherSuite>,
    ) -> Self {
        let credentials = base64::encode(credentials.serialize().as_slice().to_vec());
        Self {
            username: username.into(),
            credentials,
        }
    }
}

pub struct Client {
    password: String,
}

impl Client {
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
        }
    }

    // Step 1: Registration start
    pub fn start_registration(
        &self,
    ) -> Result<
        (
            ClientRegistration<DefaultCipherSuite>,
            RegistrationRequest<DefaultCipherSuite>,
        ),
        ProtocolError,
    > {
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
        let result = registration.finish(
            &mut rng,
            self.password.as_bytes(),
            response,
            ClientRegistrationFinishParameters::default(),
        )?;
        Ok(result.message)
    }

    // Step 3: Start login (authentication)
    pub fn start_login(
        &self,
    ) -> Result<
        (
            ClientLogin<DefaultCipherSuite>,
            opaque_ke::CredentialRequest<DefaultCipherSuite>,
        ),
        ProtocolError,
    > {
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
        let result = client_login.finish(
            self.password.as_bytes(),
            credential_response,
            ClientLoginFinishParameters::default(),
        )?;
        Ok((result.session_key.as_slice().to_vec(), result.message))
    }
}
