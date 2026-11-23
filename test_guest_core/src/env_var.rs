//! Types and body for the `env_var_consumer` test guest: a program that decodes and uses a
//! caller-supplied `env_var`, then has the loader assert it.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{ReceiveInput, Response},
    program_loader::assert_env_var,
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EnvVarConfig {
    pub multiplier: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum EnvVarConsumerMessage {
    /// Test-only: takes `header` from the caller. A real consumer pins the header it trusts.
    Use {
        header: AccountId,
        env_var: Vec<u8>,
        input: u64,
    },
}

pub fn env_var_consumer(_input: &ReceiveInput, message: EnvVarConsumerMessage) -> Response {
    let EnvVarConsumerMessage::Use {
        header,
        env_var,
        input,
    } = message;
    let config: EnvVarConfig =
        borsh::from_slice(&env_var).expect("env_var must decode as EnvVarConfig");
    let product = input
        .checked_mul(config.multiplier)
        .expect("product overflows");
    Response::set_state(product.to_le_bytes().to_vec()).send(assert_env_var(header, env_var))
}
