pub mod initialize;
pub mod register;
pub mod slash;
pub mod state;
pub mod verify_post;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProofOutput {
    pub registry_root: [u8; 32],
    pub message_hash: [u8; 32],
    pub tracing_tag: [u8; 32],
}