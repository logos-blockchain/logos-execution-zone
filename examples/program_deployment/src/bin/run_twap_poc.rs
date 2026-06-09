use std::time::Duration;

use authenticated_transfer_core::Instruction as AuthIx;
use clock_core::CLOCK_01_PROGRAM_ACCOUNT_ID;
use common::HashType;
use common::transaction::LeeTransaction;
use lee::{
    AccountId, PrivateKey, ProgramDeploymentTransaction, PublicTransaction,
    program::Program,
    program_deployment_transaction,
    public_transaction::{Message, WitnessSet},
};
use pool_stub_core::Instruction as PoolIx;
use sequencer_service_rpc::RpcClient as _;
use serde::Serialize;
use twap_core::{Instruction as TwapIx, PriceAccount};
use wallet::WalletCore;

async fn deploy(wallet: &WalletCore, path: &str) -> (Program, HashType) {
    let bytecode = std::fs::read(path).unwrap();
    let program = Program::new(bytecode.clone()).unwrap();
    let message = program_deployment_transaction::Message::new(bytecode);
    let tx = ProgramDeploymentTransaction::new(message);

    let hash = wallet
        .sequencer_client
        .send_transaction(LeeTransaction::ProgramDeployment(tx))
        .await
        .unwrap();

    (program, hash)
}

async fn call(
    wallet: &WalletCore,
    program: &Program,
    accounts: Vec<AccountId>,
    ix: impl Serialize,
    signing_keys: &[&PrivateKey],
) -> HashType {
    let instruction_data = Program::serialize_instruction(ix).unwrap();
    let nonces = wallet.get_accounts_nonces(accounts.clone()).await.unwrap();
    let message = Message::new_preserialized(program.id(), accounts, nonces, instruction_data);
    let witness_set = WitnessSet::for_message(&message, signing_keys);
    let tx = PublicTransaction::new(message, witness_set);

    wallet
        .sequencer_client
        .send_transaction(LeeTransaction::Public(tx))
        .await
        .unwrap()
}

#[tokio::main]
async fn main() {
    let mut wallet = WalletCore::from_env().unwrap();

    let args: Vec<String> = std::env::args().collect();
    let pool_bin = &args[1];
    let twap_bin = &args[2];

    let (pool_program, pool_deploy) = deploy(&wallet, pool_bin).await;
    let (twap_program, twap_deploy) = deploy(&wallet, twap_bin).await;
    tokio::time::sleep(Duration::from_millis(2000)).await;
    let mut hashes = vec![("deploy_pool", pool_deploy), ("deploy_twap", twap_deploy)];

    let (pool, _) = wallet.create_new_account_public(None);
    let (price, _) = wallet.create_new_account_public(None);
    let clock = CLOCK_01_PROGRAM_ACCOUNT_ID;

    let pool_key = wallet.get_account_public_signing_key(pool).unwrap().clone();
    let price_key = wallet.get_account_public_signing_key(price).unwrap().clone();

    let auth_program = Program::authenticated_transfer_program();
    hashes.push((
        "reg_pool",
        call(&wallet, &auth_program, vec![pool], AuthIx::Initialize, &[&pool_key]).await,
    ));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    hashes.push((
        "reg_price",
        call(&wallet, &auth_program, vec![price], AuthIx::Initialize, &[&price_key]).await,
    ));
    tokio::time::sleep(Duration::from_millis(1500)).await;

    hashes.push((
        "init_pool",
        call(&wallet, &pool_program, vec![pool], PoolIx::InitPool { tick: 0 }, &[&pool_key]).await,
    ));
    tokio::time::sleep(Duration::from_millis(1500)).await;

    for tick in [100_i32, 250, 400, 9_000_000, 600] {
        hashes.push((
            "observe",
            call(&wallet, &pool_program, vec![pool, clock], PoolIx::Observe { tick }, &[&pool_key])
                .await,
        ));
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }

    hashes.push((
        "read_twap",
        call(
            &wallet,
            &twap_program,
            vec![pool, clock, price],
            TwapIx::ReadTwap {
                window_blocks: 3,
                max_age_blocks: 100,
            },
            &[&price_key],
        )
        .await,
    ));
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let latest_block = wallet.sync_to_latest_block().await.unwrap();
    println!("latest_block={latest_block}");

    for (label, hash) in &hashes {
        let included = wallet
            .sequencer_client
            .get_transaction(*hash)
            .await
            .unwrap()
            .is_some();
        println!("{label} included={included}");
    }

    for (name, id) in [("clock", clock), ("pool", pool), ("price", price)] {
        match wallet.get_account_public(id).await {
            Ok(account) => println!("{name} data_len={}", account.data.as_ref().len()),
            Err(error) => println!("{name} get_error={error}"),
        }
    }

    let account = wallet.get_account_public(price).await.unwrap();
    match PriceAccount::try_from(&account.data) {
        Ok(price_account) => println!(
            "price={} timestamp_ms={} source_id={}",
            price_account.price, price_account.timestamp_ms, price_account.source_id
        ),
        Err(error) => println!("price_decode_failed={error}"),
    }
}
