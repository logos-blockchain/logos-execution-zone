#![no_main]

use nssa_core::account::AccountWithMetadata;
use spel_framework::prelude::*;
use membership_registry::state::ForumInstance;
use membership_registry::{initialize, register, slash, verify_post};

risc0_zkvm::guest::entry!(main);

#[lez_program]
mod forum_registry {

    #[instruction]
    pub fn initialize_forum(
        #[account(init, pda = [literal("forum"), arg("forum_id")])]
        state: AccountWithMetadata,
        #[account(signer)]
        admin: AccountWithMetadata,
        forum_id: [u8; 32],
        k_strikes: u32,
        n_moderators: u32,
        m_moderators: u32,
    ) -> SpelResult {
        let mut forum = initialize::process_initialize(k_strikes, n_moderators, m_moderators)
            .map_err(|e| spel_framework::error::SpelError::Custom { code: 1, message: e.into() })?;

        forum.admin_pubkey = *admin.account_id.value();

        let mut state_mut = state.clone();
        state_mut.account.data = borsh::to_vec(&forum)
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 2, message: "Serialization error".into() })?
            .try_into()
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 9, message: "Data too large".into() })?;

        Ok(SpelOutput::execute(vec![state_mut.account, admin.account], vec![]))
    }

    #[instruction]
    pub fn register_member(
        #[account(mut, pda = [literal("forum"), arg("forum_id")])]
        state: AccountWithMetadata,
        #[account(signer)]
        member: AccountWithMetadata,
        forum_id: [u8; 32],
        commitment: [u8; 32],
        stake_amount: u64,
    ) -> SpelResult {
        let mut forum: ForumInstance = borsh::from_slice(&state.account.data)
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 3, message: "Deserialization error".into() })?;

        let commitment_obj = borsh::from_slice(&commitment)
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 12, message: "Invalid commitment bytes".into() })?;

        register::process_register(&mut forum, commitment_obj, stake_amount)
            .map_err(|e| spel_framework::error::SpelError::Custom { code: 4, message: e.into() })?;

        let mut member_mut = member.clone();
        let stake_u128 = stake_amount as u128;
        if member_mut.account.balance < stake_u128 {
            return Err(spel_framework::error::SpelError::Custom {
                code: 13, message: "Insufficient balance for stake".into(),
            });
        }
        member_mut.account.balance -= stake_u128;

        let mut state_mut = state.clone();
        state_mut.account.data = borsh::to_vec(&forum)
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 5, message: "Serialization error".into() })?
            .try_into()
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 10, message: "Data too large".into() })?;

        Ok(SpelOutput::execute(vec![state_mut.account, member_mut.account], vec![]))
    }

    #[instruction]
    pub fn verify_post(
        #[account(mut, pda = [literal("forum"), arg("forum_id")])]
        state: AccountWithMetadata,
        forum_id: [u8; 32],
        registry_root: [u8; 32],
        tracing_tag: [u8; 32],
    ) -> SpelResult {
        let mut forum: ForumInstance = borsh::from_slice(&state.account.data)
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 14, message: "Deserialization error".into() })?;

        verify_post::process_verify_post(&mut forum, registry_root, tracing_tag)
            .map_err(|e| spel_framework::error::SpelError::Custom { code: 15, message: e.into() })?;

        let mut state_mut = state.clone();
        state_mut.account.data = borsh::to_vec(&forum)
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 16, message: "Serialization error".into() })?
            .try_into()
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 17, message: "Data too large".into() })?;

        Ok(SpelOutput::execute(vec![state_mut.account], vec![]))
    }

    #[instruction]
    pub fn slash_member(
        #[account(mut, pda = [literal("forum"), arg("forum_id")])]
        state: AccountWithMetadata,
        #[account(signer)]
        authority: AccountWithMetadata,
        forum_id: [u8; 32],
        slashed_nsk: [u8; 32],
    ) -> SpelResult {
        let mut forum: ForumInstance = borsh::from_slice(&state.account.data)
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 6, message: "Deserialization error".into() })?;

        if forum.admin_pubkey != *authority.account_id.value() {
            return Err(spel_framework::error::SpelError::Custom {
                code: 18, message: "Unauthorized: only admin can execute slashing".into(),
            });
        }

        let nsk_obj = nssa_core::NullifierSecretKey::from(slashed_nsk);
        let confiscated = slash::process_slash(&mut forum, &nsk_obj)
            .map_err(|e| spel_framework::error::SpelError::Custom { code: 7, message: e.into() })?;

        let mut authority_mut = authority.clone();
        authority_mut.account.balance += confiscated as u128;

        let mut state_mut = state.clone();
        state_mut.account.data = borsh::to_vec(&forum)
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 8, message: "Serialization error".into() })?
            .try_into()
            .map_err(|_| spel_framework::error::SpelError::Custom { code: 11, message: "Data too large".into() })?;

        Ok(SpelOutput::execute(vec![state_mut.account, authority_mut.account], vec![]))
    }
}
