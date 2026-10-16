#![expect(
    clippy::print_stdout,
    reason = "This is an example program, it's fine to print to stdout"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use clap::{Parser, Subcommand};
use common::transaction::LeeTransaction;
use lee::{
    AccountId, Actor, PrivateKey, PublicAccountEvidence, PublicKey, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use lee_core::{native_token::NATIVE_TOKEN_PROGRAM_ID, program::PdaSeed};
use program_deployment::{deploy_program, fee_paid_by};
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;

// One driver for all the example programs: deploy a guest once, then send it messages as often as
// needed. The `run_*` runners deploy again on every run; this splits the two steps so a tool (such
// as `jz-progs/prog-tui`) can keep a program's address and call it repeatedly.
//
// Every call waits for its transaction to be included, then reads back the target actor state.
// A reverted call is still included and charged, so a call that leaves the state unchanged exits
// non-zero; the revert reason is only in the sequencer's log.
//
// Results are printed as one `PROG_CLI {json}` line, after the wallet's own output. Set
// `SUPPRESS_VERBOSE_PRINTS=1` to drop the wallet's full transaction dumps.
//
// Usage:
//   cargo run --release --bin prog_cli -- --payer <payer> deploy <path/to/guest.bin>
//   cargo run --release --bin prog_cli -- --payer <payer> hello --program <id> --account <id> \
//     --text 'Hola mundo!'

// The `hello_world_with_move_function` guest's `Message::Write(data)` and
// `Message::MoveData { data, to }`, borsh-encoded as a variant index followed by the fields.
const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

// Must match `tail_call_with_pda.rs`.
const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

#[derive(Parser, Debug)]
struct Cli {
    /// An existing, funded public account in this wallet that pays every fee.
    #[arg(long)]
    payer: AccountId,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Deploy a guest `.bin` through `program_loader` and print its program id.
    Deploy { bin: String },
    /// `hello_world`: append `text` to the program's actor state on `account`.
    Hello {
        #[arg(long)]
        program: AccountId,
        #[arg(long)]
        account: AccountId,
        #[arg(long)]
        text: String,
        /// Sign with `account`'s key, as `hello_world_with_authorization` requires.
        #[arg(long)]
        sign: bool,
    },
    /// `hello_world_with_move_function`: `Write(text)` to `account`.
    MoveWrite {
        #[arg(long)]
        program: AccountId,
        #[arg(long)]
        account: AccountId,
        #[arg(long)]
        text: String,
    },
    /// `hello_world_with_move_function`: `MoveData` from one public account to another.
    MoveData {
        #[arg(long)]
        program: AccountId,
        #[arg(long)]
        from: AccountId,
        #[arg(long)]
        to: AccountId,
    },
    /// `simple_tail_call`: the caller sends a greeting to the callee's actor on `account`.
    Tail {
        #[arg(long)]
        caller: AccountId,
        #[arg(long)]
        callee: AccountId,
        #[arg(long)]
        account: AccountId,
    },
    /// `tail_call_with_pda`: the caller authorizes its PDA for the callee
    /// (`hello_world_with_authorization`) and sends it a greeting.
    Pda {
        #[arg(long)]
        caller: AccountId,
        #[arg(long)]
        callee: AccountId,
    },
}

/// A public call: the root actor, every actor it touches, and the actor state to check afterwards.
struct Call {
    to: Actor,
    actors: Vec<Actor>,
    message: Vec<u8>,
    signers: Vec<AccountId>,
    evidence: Vec<PublicAccountEvidence>,
    target: Actor,
}

/// The actor state of `actor`, or `None` when its account isn't on chain.
async fn actor_state(wallet_core: &WalletCore, actor: Actor) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(wallet_core
        .get_account_view(actor)
        .await?
        .map(|account| account.data.actor_state(actor.program_account_id).as_ref().to_vec()))
}

async fn is_on_chain(wallet_core: &WalletCore, account_id: AccountId) -> anyhow::Result<bool> {
    Ok(actor_state(wallet_core, Actor::new(account_id, NATIVE_TOKEN_PROGRAM_ID))
        .await?
        .is_some())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    })
}

/// Sends `call` paid by `payer`, waits for inclusion, and reports whether the target changed.
async fn send(wallet_core: &WalletCore, payer: AccountId, call: Call) -> anyhow::Result<()> {
    let Call {
        to,
        actors,
        message,
        signers,
        mut evidence,
        target,
    } = call;

    // A public actor only runs on an account that is on chain, signs, or is admitted by evidence.
    // Admit each fresh account this wallet holds a key for by its public key: no signature needed.
    let mut admitted = BTreeSet::new();
    for actor in &actors {
        let account_id = actor.account_id;
        if signers.contains(&account_id)
            || account_id == payer
            || !admitted.insert(account_id)
            || is_on_chain(wallet_core, account_id).await?
        {
            continue;
        }
        if let Some(key) = wallet_core.get_account_public_signing_key(account_id) {
            evidence.push(PublicAccountEvidence::Key(PublicKey::new_from_private_key(
                key,
            )));
        }
    }

    // The fee is charged to `payer`, so it signs and lists its nonce, as does every other signer.
    let (fee, payer_nonce, payer_key) = fee_paid_by(wallet_core, payer).await?;
    let mut nonces = BTreeMap::from([(payer, payer_nonce)]);
    let mut keys: Vec<PrivateKey> = vec![payer_key];
    for &signer in signers.iter().filter(|&&signer| signer != payer) {
        let key = wallet_core
            .get_account_public_signing_key(signer)
            .ok_or_else(|| anyhow::anyhow!("signer {signer} is not a public account in this wallet"))?
            .clone();
        nonces.insert(signer, wallet_core.get_accounts_nonces(&[signer]).await?[0]);
        keys.push(key);
    }

    let before = actor_state(wallet_core, target).await?;
    let message = Message::new(to, message, actors, nonces, Some(fee), evidence);
    let key_refs: Vec<&PrivateKey> = keys.iter().collect();
    let witness_set = WitnessSet::for_message(&message, &key_refs);
    let tx = PublicTransaction::new(message, witness_set);

    let tx_hash = wallet_core
        .client_owned()
        .send_transaction(LeeTransaction::Public(tx))
        .await?;
    let tx_hex = tx_hash.to_string();
    println!("Transaction hash is {tx_hex}");
    let (_, block_id) = wallet_core.poll_transaction(tx_hash).await?;
    println!("Transaction is included in block {block_id}");

    let after = actor_state(wallet_core, target).await?;
    let changed = before != after;
    println!(
        "PROG_CLI {{\"tx\":\"{tx_hex}\",\"block\":{block_id},\"account\":\"{}\",\"program\":\"{}\",\"state_hex\":\"{}\",\"changed\":{changed}}}",
        target.account_id,
        target.program_account_id,
        hex(&after.unwrap_or_default()),
    );
    anyhow::ensure!(
        changed,
        "included in block {block_id}, but the target actor state didn't change: the call \
         probably reverted (the reason is in the sequencer's log)"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let payer = cli.payer;
    let mut wallet_core = WalletCore::from_env()?;

    let call = match cli.command {
        Command::Deploy { bin } => {
            let bytecode = std::fs::read(&bin)?;
            // `deploy_program` prints the `PROG_CLI {"program_id":…}` line itself.
            deploy_program(&mut wallet_core, bytecode, payer).await?;
            return Ok(());
        }
        Command::Hello {
            program,
            account,
            text,
            sign,
        } => {
            let hello = Actor::new(account, program);
            Call {
                to: hello,
                actors: vec![hello],
                message: Program::serialize_message(text.into_bytes())?,
                signers: if sign { vec![account] } else { Vec::new() },
                evidence: Vec::new(),
                target: hello,
            }
        }
        Command::MoveWrite {
            program,
            account,
            text,
        } => {
            let actor = Actor::new(account, program);
            Call {
                to: actor,
                actors: vec![actor],
                message: Program::serialize_message((WRITE_FUNCTION_ID, text.into_bytes()))?,
                signers: Vec::new(),
                evidence: Vec::new(),
                target: actor,
            }
        }
        Command::MoveData { program, from, to } => {
            let source = Actor::new(from, program);
            let destination = Actor::new(to, program);
            // The guest refuses unless `data` is exactly what the source holds.
            let moved = actor_state(&wallet_core, source).await?.unwrap_or_default();
            Call {
                to: source,
                actors: vec![source, destination],
                message: Program::serialize_message((MOVE_DATA_FUNCTION_ID, moved, to))?,
                signers: Vec::new(),
                evidence: Vec::new(),
                target: destination,
            }
        }
        Command::Tail {
            caller,
            callee,
            account,
        } => {
            let caller = Actor::new(account, caller);
            let callee = Actor::new(account, callee);
            Call {
                to: caller,
                actors: vec![caller, callee],
                message: Program::serialize_message(callee)?,
                signers: Vec::new(),
                evidence: Vec::new(),
                target: callee,
            }
        }
        Command::Pda { caller, callee } => {
            let pda = AccountId::for_public_pda(&caller, &PDA_SEED);
            println!("The program derived account id is: {pda}");
            let caller_actor = Actor::new(pda, caller);
            let callee_actor = Actor::new(pda, callee);
            Call {
                to: caller_actor,
                actors: vec![caller_actor, callee_actor],
                message: Program::serialize_message(callee)?,
                signers: Vec::new(),
                evidence: vec![PublicAccountEvidence::Pda {
                    program: caller,
                    seed: PDA_SEED,
                }],
                target: callee_actor,
            }
        }
    };
    send(&wallet_core, payer, call).await
}
