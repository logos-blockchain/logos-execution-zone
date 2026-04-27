#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration test file, not inside a #[cfg(test)] module"
)]

//! Group-owned private PDA lifecycle integration test.
//!
//! Demonstrates:
//! 1. GMS creation and sealed distribution between controllers.
//! 2. Key agreement: both controllers derive identical keys from the shared GMS.
//! 3. Forward secrecy: ratcheting the GMS produces different keys, locking out removed members.

use anyhow::{Context as _, Result};
use integration_tests::TestContext;
use key_protocol::key_management::group_key_holder::GroupKeyHolder;
use log::info;
use nssa::{AccountId, program::Program};
use nssa_core::program::PdaSeed;
use tokio::test;

/// Group PDA lifecycle: create group, distribute GMS, verify key agreement, revoke.
#[test]
async fn group_pda_lifecycle() -> Result<()> {
    let ctx = TestContext::new().await?;

    let alice_holder = GroupKeyHolder::new();
    assert_eq!(alice_holder.epoch(), 0);
    let pda_seed = PdaSeed::new([42_u8; 32]);
    let group_pda_spender =
        Program::new(test_program_methods::GROUP_PDA_SPENDER_ELF.to_vec()).unwrap();

    // -----------------------------------------------------------------------
    // Act 1: GMS creation and sealed distribution
    // -----------------------------------------------------------------------

    info!("Act 1: creating group and distributing GMS");

    let alice_npk = alice_holder
        .derive_keys_for_pda(&pda_seed)
        .generate_nullifier_public_key();

    let bob_private_account = ctx.existing_private_accounts()[1];
    let (bob_keychain, _) = ctx
        .wallet()
        .storage()
        .user_data
        .get_private_account(bob_private_account)
        .cloned()
        .context("Bob's private account not found")?;

    // Alice seals GMS for Bob, Bob unseals
    let sealed = alice_holder.seal_for(&bob_keychain.viewing_public_key);
    let bob_holder =
        GroupKeyHolder::unseal(&sealed, &bob_keychain.private_key_holder.viewing_secret_key)
            .expect("Bob should unseal the GMS");

    // -----------------------------------------------------------------------
    // Act 2: Key agreement
    //
    // Both controllers independently derive identical keys for the same PDA
    // seed. Neither communicated any per-PDA keys — they derived them from
    // the shared GMS.
    // -----------------------------------------------------------------------

    info!("Act 2: verifying key agreement");

    let bob_npk = bob_holder
        .derive_keys_for_pda(&pda_seed)
        .generate_nullifier_public_key();
    assert_eq!(
        alice_npk, bob_npk,
        "Key agreement: identical NPK from shared GMS"
    );

    let group_account_id =
        AccountId::for_private_pda(&group_pda_spender.id(), &pda_seed, &alice_npk);
    info!("Group PDA AccountId: {group_account_id}");

    // Both derive the same AccountId independently
    let bob_account_id = AccountId::for_private_pda(&group_pda_spender.id(), &pda_seed, &bob_npk);
    assert_eq!(group_account_id, bob_account_id);

    info!("Act 2 complete: key agreement verified");

    // -----------------------------------------------------------------------
    // Act 3: Revocation and forward secrecy
    //
    // Alice ratchets the GMS to exclude Bob. The new keys produce a different
    // NPK and therefore a different AccountId. Bob's frozen holder can no
    // longer derive the new keys.
    // -----------------------------------------------------------------------

    info!("Act 3: ratchet and forward secrecy");

    let mut ratcheted_holder = alice_holder;
    ratcheted_holder.ratchet([99_u8; 32]);
    assert_eq!(ratcheted_holder.epoch(), 1);

    let ratcheted_npk = ratcheted_holder
        .derive_keys_for_pda(&pda_seed)
        .generate_nullifier_public_key();

    let bob_stale_npk = bob_holder
        .derive_keys_for_pda(&pda_seed)
        .generate_nullifier_public_key();

    // Forward secrecy: ratcheted keys differ from Bob's stale keys
    assert_ne!(ratcheted_npk, bob_stale_npk);
    assert_ne!(ratcheted_npk, alice_npk);

    // Different AccountId after ratchet
    let new_account_id =
        AccountId::for_private_pda(&group_pda_spender.id(), &pda_seed, &ratcheted_npk);
    assert_ne!(group_account_id, new_account_id);

    // Bob's stale keys still point to the old address
    let bob_stale_account_id =
        AccountId::for_private_pda(&group_pda_spender.id(), &pda_seed, &bob_stale_npk);
    assert_eq!(bob_stale_account_id, group_account_id);
    assert_ne!(bob_stale_account_id, new_account_id);

    // Sealed round-trip of ratcheted GMS
    let (alice_kc, _) = ctx
        .wallet()
        .storage()
        .user_data
        .get_private_account(ctx.existing_private_accounts()[0])
        .cloned()
        .context("Alice's keys not found")?;
    let sealed_ratcheted = ratcheted_holder.seal_for(&alice_kc.viewing_public_key);
    let restored = GroupKeyHolder::unseal(
        &sealed_ratcheted,
        &alice_kc.private_key_holder.viewing_secret_key,
    )
    .expect("Should unseal ratcheted GMS");
    assert_eq!(
        restored.dangerous_raw_gms(),
        ratcheted_holder.dangerous_raw_gms()
    );
    assert_eq!(restored.epoch(), 1);

    info!("Act 3 complete: forward secrecy verified");
    info!("Group PDA lifecycle test complete");
    Ok(())
}
