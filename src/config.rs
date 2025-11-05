use serde_derive::{Serialize, Deserialize};

pub trait Configuration {
    fn discoverable(&self) -> bool;
    
}