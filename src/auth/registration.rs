use serde_derive::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub email: String,
    pub gender: Option<String>,
}
