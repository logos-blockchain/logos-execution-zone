use std::time::Duration;

use clock_core::CLOCK_01_PROGRAM_ACCOUNT_ID;
use common::HashType;
use common::transaction::LeeTransaction;
use lee::{ProgramDeploymentTransaction, program::Program, program_deployment_transaction};
use pool_stub_core::Instruction as PoolIx;
use sequencer_service_rpc::RpcClient as _;
use serde::Serialize;
use twap_core::{Instruction as TwapIx, PriceAccount};
use wallet::{AccountIdentity, WalletCore};

async fn await_included(wallet: &WalletCore, hash: HashType) {
    for _ in 0..60 {
        if wallet
            .sequencer_client
            .get_transaction(hash)
            .await
            .unwrap()
            .is_some()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
}

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
    await_included(wallet, hash).await;

    (program, hash)
}

async fn call(
    wallet: &WalletCore,
    program: &Program,
    accounts: Vec<AccountIdentity>,
    ix: impl Serialize,
) -> HashType {
    let instruction_data = Program::serialize_instruction(ix).unwrap();

    let hash = wallet
        .send_pub_tx(accounts, instruction_data, &program.clone().into())
        .await
        .unwrap();
    await_included(wallet, hash).await;

    hash
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

    hashes.push((
        "init_pool",
        call(&wallet, &pool_program, vec![AccountIdentity::Public(pool)], PoolIx::InitPool { tick: 0 })
            .await,
    ));
    tokio::time::sleep(Duration::from_millis(1500)).await;

    for tick in [100_i32, 250, 400, 9_000_000, 600] {
        hashes.push((
            "observe",
            call(
                &wallet,
                &pool_program,
                vec![
                    AccountIdentity::Public(pool),
                    AccountIdentity::PublicNoSign(clock),
                ],
                PoolIx::Observe { tick },
            )
            .await,
        ));
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }

    hashes.push((
        "read_twap",
        call(
            &wallet,
            &twap_program,
            vec![
                AccountIdentity::PublicNoSign(pool),
                AccountIdentity::Public(price),
                AccountIdentity::PublicNoSign(clock),
            ],
            TwapIx::ReadTwap {
                window_ms: 6_000,
                max_age_ms: 600_000,
            },
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
