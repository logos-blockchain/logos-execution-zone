#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

//! A private actor's grant used by public programs end to end: handed to them mid execution, and
//! held by a public root through `private_signers`. The public programs (`grant_relay`) never name
//! whose grant they hold, as a privacy-agnostic program wouldn't.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    TestContext, account_balance, funded_private_account, new_account, private_balance,
    sync_private, wait_for_inclusion,
};
use lee::{
    AccountId, Actor, privacy_preserving_transaction::circuit::ProgramCatalog, program::Program,
};
use lee_core::program::SyncMessage;
use sequencer_service_rpc::RpcClient as _;
use test_guest_core::{Relay, Script};
use tokio::test;
use wallet::{AccountIdentity, AccountMention, program_facades::program_loader::ProgramLoader};

const AMOUNT: u128 = 7;
const FUNDING: u128 = 10_000_000;
const OPENING: [u8; 32] = [42; 32];

// A funded private `alice`, and public `router` and `pool` actors running `grant_relay`; the pool
// pays out to `recipient`.
struct Setup {
    alice: AccountId,
    scripted: AccountId,
    relay: AccountId,
    router: Actor,
    pool: Actor,
    recipient: AccountId,
}

impl Setup {
    async fn new(ctx: &mut TestContext) -> Result<Self> {
        let scripted = deploy(ctx, &test_programs::scripted()).await?;
        let relay = deploy(ctx, &test_programs::grant_relay()).await?;
        let alice = funded_private_account(ctx, FUNDING).await?;
        let [first, second] = [
            ctx.existing_public_accounts()[0],
            ctx.existing_public_accounts()[1],
        ];
        Ok(Self {
            alice,
            scripted,
            relay,
            router: Actor::new(first, relay),
            pool: Actor::new(second, relay),
            recipient: second,
        })
    }

    fn programs(&self) -> ProgramCatalog {
        ProgramCatalog::from([
            (self.scripted, test_programs::scripted()),
            (self.relay, test_programs::grant_relay()),
        ])
    }

    fn relay(&self) -> Relay {
        Relay {
            via: vec![self.pool],
            to: self.recipient,
            amount: AMOUNT,
        }
    }

    fn public_mentions(&self) -> Vec<AccountMention> {
        vec![
            AccountIdentity::Public(self.router.account_id)
                .select_program_actor_state(self.relay)
                .without_authorization(),
            AccountIdentity::Public(self.pool.account_id)
                .select_program_actor_state(self.relay)
                .without_authorization(),
            AccountIdentity::Public(self.recipient)
                .balance()
                .without_authorization(),
        ]
    }

    // Sends the transaction and returns the recipient's gain and alice's loss.
    async fn run(
        &self,
        ctx: &mut TestContext,
        accounts: Vec<AccountMention>,
        root: usize,
        message: Vec<u8>,
    ) -> Result<(u128, u128, LeeTransaction)> {
        let (recipient_before, alice_before) = (
            account_balance(ctx, self.recipient).await?,
            private_balance(ctx, self.alice)?,
        );
        let (hash, _) = ctx
            .wallet()
            .send_privacy_preserving_tx(accounts, root, message, &self.programs())
            .await
            .context("the transaction should be sent")?;
        wait_for_inclusion(ctx, hash).await?;
        sync_private(ctx).await?;
        let (tx, _) = ctx
            .sequencer_client()
            .get_transaction(hash)
            .await?
            .context("the included transaction should be served")?;
        let received = account_balance(ctx, self.recipient)
            .await?
            .checked_sub(recipient_before)
            .context("the recipient's balance should not fall")?;
        let spent = alice_before
            .checked_sub(private_balance(ctx, self.alice)?)
            .context("alice's balance should not grow")?;
        Ok((received, spent, tx))
    }
}

async fn deploy(ctx: &mut TestContext, program: &Program) -> Result<AccountId> {
    let payer = ctx.existing_public_accounts()[0];
    let header = new_account(ctx, false, None).await?;
    let mut segments = Vec::new();
    for _ in program
        .user_elf()?
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
    {
        segments.push(new_account(ctx, false, None).await?);
    }
    ProgramLoader(ctx.wallet())
        .deploy(header, &segments, program.elf().to_vec(), true, Some(payer))
        .await
}

// Alice's private root hands the public router her balance's grant; the router hands it to the
// pool, which debits her: the grant crosses out under her address and is used publicly.
#[test]
async fn a_private_actors_grant_handed_mid_execution_is_used_by_public_programs() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let setup = Setup::new(&mut ctx).await?;
    let balance = Actor::native_balance(setup.alice);

    for lends in [true, false] {
        let call = SyncMessage::new(setup.router, &setup.relay());
        let script = Script::default().send(if lends {
            call.with_grants([balance])
        } else {
            call
        });
        let accounts = [
            vec![
                AccountIdentity::PrivateOwned(setup.alice)
                    .select_program_actor_state(setup.scripted),
                AccountIdentity::PrivateOwned(setup.alice).balance(),
            ],
            setup.public_mentions(),
        ]
        .concat();

        let (received, spent, _) = setup
            .run(
                &mut ctx,
                accounts,
                0,
                Program::serialize_message(script).expect("Script should serialize"),
            )
            .await?;

        assert_eq!(received, if lends { AMOUNT } else { 0 }, "lends {lends}");
        assert!(spent >= received, "lends {lends}: alice spent {spent}");
    }
    Ok(())
}

// The public router is the root; the wallet declares alice's mention under its opening in
// `private_signers`, so the router holds her grant and the pool debits her with it. Without an
// opening nothing is declared, and the router holds nothing.
#[test]
async fn a_private_signer_declared_for_a_public_root_is_used_by_public_programs() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let setup = Setup::new(&mut ctx).await?;

    for opened in [true, false] {
        let alice = AccountMention {
            address_openings: if opened {
                BTreeSet::from([OPENING])
            } else {
                BTreeSet::new()
            },
            ..AccountIdentity::PrivateOwned(setup.alice).balance()
        };
        let accounts = [setup.public_mentions(), vec![alice]].concat();

        let (received, spent, tx) = setup
            .run(
                &mut ctx,
                accounts,
                0,
                Program::serialize_message(setup.relay()).expect("Relay should serialize"),
            )
            .await?;

        let LeeTransaction::PrivacyPreserving(tx) = tx else {
            anyhow::bail!("a transaction with a private account is privacy preserving");
        };
        let declared = if opened {
            BTreeSet::from([Actor::native_balance(setup.alice.blinded(&OPENING))])
        } else {
            BTreeSet::new()
        };
        assert_eq!(
            tx.message.public_context.private_signers, declared,
            "opened {opened}"
        );
        assert_eq!(received, if opened { AMOUNT } else { 0 }, "opened {opened}");
        assert!(spent >= received, "opened {opened}: alice spent {spent}");
    }
    Ok(())
}
