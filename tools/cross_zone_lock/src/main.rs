//! Thin CLI for the real (docker-compose) cross-zone bridge demo.
//!
//! Two jobs:
//!   `--print-params` prints the derived values the zone config files need
//!     (program ids as `[u32; 8]`, and the holder's base58 account id), so the
//!     JSON configs stay in sync with the built guests.
//!   the default mode builds a signed `bridge_lock::Lock` and submits it to zone
//!     A's sequencer RPC, addressed to the recipient on zone B.
//!
//! Usage:
//!   cross_zone_lock --print-params
//!   cross_zone_lock --sequencer-url http://localhost:3040 --target-zone <64-hex channel id of zone B>
//!                   [--amount 30] [--recipient <64-hex>]

use anyhow::{Context as _, Result, bail};
use common::transaction::LeeTransaction;
use cross_zone_outbox_core::outbox_pda;
use lee::{
    AccountId, PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use sequencer_service_rpc::{RpcClient as _, SequencerClientBuilder};

/// Genesis holder key (matches `supply_bridge_lock_holding` in zone A's config).
const HOLDER_KEY_SEED: [u8; 32] = [7; 32];
const DEFAULT_AMOUNT: u128 = 30;
const DEFAULT_RECIPIENT: [u8; 32] = [9; 32];

fn holder() -> (PrivateKey, AccountId) {
    let key = PrivateKey::try_new(HOLDER_KEY_SEED).expect("valid holder key");
    let id = AccountId::from(&PublicKey::new_from_private_key(&key));
    (key, id)
}

fn print_params() {
    let (_, holder_id) = holder();
    let params = serde_json::json!({
        "bridge_lock_id": programs::bridge_lock().id(),
        "wrapped_token_id": programs::wrapped_token().id(),
        "cross_zone_outbox_id": programs::cross_zone_outbox().id(),
        "cross_zone_inbox_id": programs::cross_zone_inbox().id(),
        "holder_id_base58": holder_id.to_string(),
        "holder_key_seed": HOLDER_KEY_SEED,
        "default_recipient": DEFAULT_RECIPIENT,
        "recipient_wrapped_holding_id_base58":
            wrapped_token_core::holding_account_id(programs::wrapped_token().id(), &DEFAULT_RECIPIENT)
                .to_string(),
    });
    println!("{}", serde_json::to_string_pretty(&params).expect("serialize params"));
}

fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).with_context(|| format!("{what} must be hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must be 32 bytes (64 hex chars)"))
}

fn build_lock_tx(
    holder_key: &PrivateKey,
    holder_id: AccountId,
    target_zone: [u8; 32],
    recipient: [u8; 32],
    amount: u128,
) -> LeeTransaction {
    let bridge_lock_id = programs::bridge_lock().id();
    let wrapped_token_id = programs::wrapped_token().id();
    let outbox_id = programs::cross_zone_outbox().id();
    let ordinal = 0;

    let mint = wrapped_token_core::Instruction::Mint { recipient, amount };
    let words = risc0_zkvm::serde::to_vec(&mint).expect("serialize mint");
    let payload: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();

    let target_accounts = vec![
        wrapped_token_core::config_account_id(wrapped_token_id).into_value(),
        wrapped_token_core::holding_account_id(wrapped_token_id, &recipient).into_value(),
    ];
    let lock = bridge_lock_core::Instruction::Lock {
        amount,
        target_zone,
        target_program_id: wrapped_token_id,
        target_accounts,
        payload,
        outbox_program_id: outbox_id,
        ordinal,
    };

    let accounts = vec![
        holder_id,
        bridge_lock_core::escrow_account_id(bridge_lock_id),
        outbox_pda(outbox_id, &target_zone, ordinal),
    ];
    let message = Message::try_new(bridge_lock_id, accounts, vec![0_u128.into()], lock)
        .expect("build lock message");
    let witness = WitnessSet::for_message(&message, &[holder_key]);
    LeeTransaction::Public(PublicTransaction::new(message, witness))
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|a| a == "--print-params") {
        print_params();
        return Ok(());
    }

    let url = arg("--sequencer-url")
        .context("missing --sequencer-url (zone A's sequencer RPC), or pass --print-params")?;
    let target_zone = parse_hex32(
        &arg("--target-zone").context("missing --target-zone (zone B's channel id, 64 hex)")?,
        "--target-zone",
    )?;
    let amount = arg("--amount")
        .map(|a| a.parse::<u128>().context("--amount must be a number"))
        .transpose()?
        .unwrap_or(DEFAULT_AMOUNT);
    let recipient = match arg("--recipient") {
        Some(s) => parse_hex32(&s, "--recipient")?,
        None => DEFAULT_RECIPIENT,
    };

    let (holder_key, holder_id) = holder();
    let tx = build_lock_tx(&holder_key, holder_id, target_zone, recipient, amount);

    let client = SequencerClientBuilder::default()
        .build(&url)
        .with_context(|| format!("failed to build sequencer client for {url}"))?;
    let hash = client
        .send_transaction(tx)
        .await
        .context("failed to submit lock to zone A")?;
    println!("submitted lock of {amount} to zone A, tx hash {hash:?}");
    println!("watch zone B's indexer for the wrapped-token mint to the recipient");
    if amount == 0 {
        bail!("amount was zero; nothing meaningful locked");
    }
    Ok(())
}
