use serde_derive::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenResponse {
    pub token: String,
    pub room: String,
    pub url: String,
}