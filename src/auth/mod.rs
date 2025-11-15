pub mod challenge;
pub mod registration;
use crate::client::auth::Client;
use crate::errors::ProtocolError;
use crate::server::auth::Server;
use serde_derive::{Deserialize, Serialize};

pub struct DefaultCipherSuite;

use opaque_ke::CipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LoginResult {
    /// Login Successful Access Token Within.
    Success(String),
    /// Password reset required, prompt user, or generate appropriately
    PasswordReset,
    Unauthorized,
    UnknownServer(String),
}

/// takes in a username and password and produces a ServerRegistration
pub fn register_user(
    server: &Server,
    username: impl Into<String>,
    password: impl Into<String>,
) -> Result<crate::server::auth::ServerRegistration, ProtocolError> {
    let client = Client::new(password);
    let (client_reg, regreq) = client.start_registration()?;
    let response = server.start_registration(regreq, username)?;
    let upload = client.finish_registration(client_reg, response)?;
    Ok(server.finish_registration(upload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::auth::LoginRequest;
    use crate::server::auth::CredentialRequest;
    use crate::server::auth::LoginResponse;
    use crate::{client::auth::Client, server::auth::Server};
    use opaque_ke::errors::ProtocolError;
    use rand::rngs::OsRng;
    use uuid::Uuid;

    #[test]
    fn serialization_round_trip() -> Result<(), crate::errors::Error> {
        let setup = ServerSetup::new(&mut OsRng);
        let server = Server::new(setup);
        let stored = register_user(&server, "user", "password")?;
        let mut client = Client::new("password");
        //let mut server = Server::new();

        // === Login phase ===
        let (client_login, credential_request) = client.start_login()?;

        let request = LoginRequest::new("user", credential_request.clone());
        let request_json = serde_json::to_string(&request)?;
        let parsed_request = serde_json::from_str(&request_json)?;

        assert_eq!(request, parsed_request);
        let parsed_credential_request = CredentialRequest::deserialize(&base64::decode(
            &parsed_request.credentials.as_bytes(),
        )?)?;
        assert_eq!(parsed_credential_request, credential_request);

        let (server_login, credential_response) =
            server.start_login(stored.clone(), parsed_credential_request, "user")?;

        let response = LoginResponse::PAKE((Uuid::new_v4(), credential_response));
        let response_json = serde_json::to_string(&response)?;
        let parsed_response = serde_json::from_str(&response_json)?;

        assert_eq!(response, parsed_response);
        let parsed_login_response = match parsed_response {
            LoginResponse::PAKE((_, resp)) => resp,
            _ => panic!("basic sanity check failed"),
        };

        let (client_key, client_finalization) =
            client.finish_login(client_login, parsed_login_response)?;

        let server_key = server.finish_login(server_login, client_finalization)?;
        assert_eq!(client_key, server_key);
        Ok(())
    }

    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_registration_flow() -> Result<(), ProtocolError> {
        init_logger();
        let setup = ServerSetup::new(&mut OsRng);
        let server = Server::new(setup);
        let client = Client::new("correct horse battery staple");

        // === Step 1: Client starts registration ===
        let (client_reg, reg_request) = client.start_registration()?;

        // === Step 2: Server processes registration request ===
        let reg_response = server.start_registration(reg_request, "alice")?;

        // === Step 3: Client finalizes registration ===
        let upload = client.finish_registration(client_reg, reg_response)?;

        // === Step 4: Server stores registration record ===
        let stored = server.finish_registration(upload);

        // Verify server stores a valid record
        assert!(
            !stored.serialize().is_empty(),
            "server stored empty registration record"
        );

        Ok(())
    }

    #[test]
    fn test_full_login_flow() -> Result<(), ProtocolError> {
        init_logger();
        let setup = ServerSetup::new(&mut OsRng);
        let server = Server::new(setup);
        let client = Client::new("hunter2");

        // === Registration phase ===
        let (client_reg, reg_request) = client.start_registration()?;
        let reg_response = server.start_registration(reg_request, "bob")?;
        let upload = client.finish_registration(client_reg, reg_response)?;
        let stored = server.finish_registration(upload);

        // === Login phase ===
        let (client_login, credential_request) = client.start_login()?;
        let (server_login, credential_response) =
            server.start_login(stored.clone(), credential_request, "bob")?;
        let (client_key, client_finalization) =
            client.finish_login(client_login, credential_response)?;
        let server_key = server.finish_login(server_login, client_finalization)?;

        // === Verify both session keys match ===
        assert_eq!(
            client_key, server_key,
            "Session keys derived by client and server should match"
        );

        Ok(())
    }

    #[test]
    fn test_login_with_wrong_password_fails() -> Result<(), ProtocolError> {
        init_logger();
        let setup = ServerSetup::new(&mut OsRng);
        let server = Server::new(setup);
        let client_good = Client::new("letmein");
        let client_bad = Client::new("wrongpassword");

        // === Registration with correct password ===
        let (client_reg, reg_request) = client_good.start_registration()?;
        let reg_response = server.start_registration(reg_request, "carol")?;
        let upload = client_good.finish_registration(client_reg, reg_response)?;
        let stored = server.finish_registration(upload);

        // === Attempt login with wrong password ===
        let (client_login, credential_request) = client_bad.start_login()?;
        let (server_login, credential_response) =
            server.start_login(stored.clone(), credential_request, "carol")?;

        // The finalization should fail due to incorrect password
        let result = client_bad.finish_login(client_login, credential_response);
        assert!(result.is_err(), "Login should fail with wrong password");

        Ok(())
    }

    #[test]
    fn test_multiple_users_independent_keys() -> Result<(), ProtocolError> {
        init_logger();
        let setup = ServerSetup::new(&mut OsRng);
        let server = Server::new(setup);

        let alice = Client::new("password123");
        let bob = Client::new("hunter2");

        // Register Alice
        let (reg_a, req_a) = alice.start_registration()?;
        let resp_a = server.start_registration(req_a, "alice")?;
        let up_a = alice.finish_registration(reg_a, resp_a)?;
        let stored_a = server.finish_registration(up_a);

        // Register Bob
        let (reg_b, req_b) = bob.start_registration()?;
        let resp_b = server.start_registration(req_b, "bob")?;
        let up_b = bob.finish_registration(reg_b, resp_b)?;
        let stored_b = server.finish_registration(up_b);

        // Login as Alice
        let (login_a, req_login_a) = alice.start_login()?;
        let (srv_login_a, resp_login_a) =
            server.start_login(stored_a.clone(), req_login_a, "alice")?;
        let (alice_key, fin_a) = alice.finish_login(login_a, resp_login_a)?;
        let server_key_a = server.finish_login(srv_login_a, fin_a)?;

        // Login as Bob
        let (login_b, req_login_b) = bob.start_login()?;
        let (srv_login_b, resp_login_b) =
            server.start_login(stored_b.clone(), req_login_b, "bob")?;
        let (bob_key, fin_b) = bob.finish_login(login_b, resp_login_b)?;
        let server_key_b = server.finish_login(srv_login_b, fin_b)?;

        // Keys for different users must not match
        assert_ne!(
            alice_key, bob_key,
            "Session keys for different users must not be equal"
        );
        assert_eq!(alice_key, server_key_a, "Alice's key must match server's");
        assert_eq!(bob_key, server_key_b, "Bob's key must match server's");

        Ok(())
    }

    #[test]
    fn test_repeated_login_produces_unique_keys() -> Result<(), ProtocolError> {
        init_logger();
        let setup = ServerSetup::new(&mut OsRng);
        let server = Server::new(setup);
        let client = Client::new("purplemonkeydishwasher");

        // Registration
        let (client_reg, reg_req) = client.start_registration()?;
        let reg_resp = server.start_registration(reg_req, "eve")?;
        let upload = client.finish_registration(client_reg, reg_resp)?;
        let stored = server.finish_registration(upload);

        // Login 1
        let (login1, req1) = client.start_login()?;
        let (srv1, resp1) = server.start_login(stored.clone(), req1, "eve")?;
        let (key1, fin1) = client.finish_login(login1, resp1)?;
        let srv_key1 = server.finish_login(srv1, fin1)?;

        // Login 2
        let (login2, req2) = client.start_login()?;
        let (srv2, resp2) = server.start_login(stored.clone(), req2, "eve")?;
        let (key2, fin2) = client.finish_login(login2, resp2)?;
        let srv_key2 = server.finish_login(srv2, fin2)?;

        // Each session must produce a distinct shared key
        assert_ne!(
            key1, key2,
            "Each login should produce a new unique session key"
        );
        assert_eq!(key1, srv_key1);
        assert_eq!(key2, srv_key2);

        Ok(())
    }
}
