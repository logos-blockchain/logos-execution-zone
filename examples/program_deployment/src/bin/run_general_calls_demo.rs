use common::transaction::NSSATransaction;
use nssa::{
    PublicTransaction,
    public_transaction::{Message, WitnessSet},
    program::Program,
};
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;
use wallet::poller::TxPoller;
use lez_sdk::routing::GeneralCallInstruction;
use risc0_zkvm::serde::to_vec;

/// Helper to wrap instructions in the GeneralCallInstruction format
fn create_user_instruction(function_id: &str, args_u32: Vec<u32>) -> GeneralCallInstruction {
    GeneralCallInstruction {
        route: None, 
        function_id: function_id.to_string(),
        args: args_u32, 
    }
}

#[tokio::main]
async fn main() {
    println!("=====================================================================");
    println!(" 🚀 LEZ General Calls via Tail Calls (LP-0015) E2E Demo");
    println!("=====================================================================\n");

    // =====================================================================
    // 0. DYNAMICALLY LOADING THE PROGRAM (Standalone Client Pattern)
    // =====================================================================
    println!("Loading Program Binary (.bin) from the artifacts directory...");
    
    // Read the .bin file that has already been wrapped with the Image ID (not raw ELF)
    let elf_a = std::fs::read("artifacts/test_program_methods/demo_call_a.bin")
        .expect("Binary A not found! Make sure you have already run 'just build-artifacts'.");
    let elf_b = std::fs::read("artifacts/test_program_methods/demo_call_b.bin")
        .expect("Binary B not found!");

    // Extract the Program ID (Cryptographic Hash) from the binary
    let prog_a = Program::new(elf_a).unwrap();
    let prog_b = Program::new(elf_b).unwrap();

    let demo_call_a_id = prog_a.id();
    let demo_call_b_id = prog_b.id();

    println!("✅ Program A ID: {:?}", demo_call_a_id);
    println!("✅ Program B ID: {:?}\n", demo_call_b_id);

    // Initialize the RPC connection to the real local sequencer
    let wallet_core = WalletCore::from_env().expect("Failed to initialize WalletCore.");
    // Initialize TxPoller using config and client from wallet_core
    let poller = TxPoller::new(&wallet_core.config(), wallet_core.sequencer_client.clone());

    // =====================================================================
    // SCENARIO 1: POSITIVE (User -> A -> B -> A)
    // =====================================================================
    println!("✅ SCENARIO 1: Running normal CPS execution...");
    
    let user_args = (1u64, 500u64, demo_call_b_id);
    let args_u32 = to_vec(&user_args).unwrap();
    let instruction_data = create_user_instruction("start_chain", args_u32);

    let message_positive = Message::try_new(
        demo_call_a_id, 
        vec![], 
        vec![], 
        instruction_data
    ).unwrap();
    
    let witness_set_positive = WitnessSet::for_message(&message_positive, &[]);
    let tx_positive = PublicTransaction::new(message_positive, witness_set_positive);

    println!("   [Positive] Sending transaction to the Local Sequencer...");
    println!("   (ZK proving is in progress, please wait a moment...)");
    
    let response_positive = wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx_positive))
        .await;

    match response_positive {
        Ok(_) => println!("   ✅ SUCCESS: Transaction processed, proof validated, and state committed!\n"),
        Err(e) => println!("   ❌ FAILED: Transaction failed. Error: {:?}\n", e),
    }

    // =====================================================================
    // SCENARIO 2: NEGATIVE (Direct Access Prevention)
    // =====================================================================
    println!("🛡️ SCENARIO 2: Attempting to bypass the router and call an internal function...");
    
    let fake_local_state = (1u64, 1000u64);
    let fake_success = true;
    let fake_args = (fake_local_state, fake_success);
    let args_u32 = to_vec(&fake_args).unwrap();
    
    let instruction_data = create_user_instruction("continue_chain", args_u32);

    let message_negative = Message::try_new(
        demo_call_a_id, 
        vec![], 
        vec![], 
        instruction_data
    ).unwrap();
    
    let witness_set_negative = WitnessSet::for_message(&message_negative, &[]);
    let tx_negative = PublicTransaction::new(message_negative, witness_set_negative);

    println!("   [Negative] Sending manipulation transaction to the Local Sequencer...");
    
    let response_negative = wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx_negative))
        .await;

    match response_negative {
        Ok(tx_hash) => { 
            println!("   Transaction accepted into the mempool. Waiting for VM execution...");
            
            match poller.poll_tx(tx_hash).await {
                Ok(_final_tx) => {
                    println!("   ❌ FATAL: The transaction executed successfully even though it should have been prohibited!");
                },
                Err(e) => {
                    println!("   ✅ SUCCESS (REJECTED): The transaction was aborted by the VM. Error: {}", e);
                }
            }
        },
        Err(e) => println!("   ✅ SUCCESS (REJECTED): Rejected at the RPC/Mempool level. Error: {}", e),
    }

    println!("E2E RPC Client Demo Complete!");
}