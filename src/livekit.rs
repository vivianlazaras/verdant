use serde_derive::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenResponse {
    pub room_id: Uuid,
    pub token: String,
    pub room: String,
    pub url: String,
}