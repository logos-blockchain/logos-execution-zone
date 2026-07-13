#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

//! M6 ingress guard: the cross-zone inbox is sequencer-only. Only the watcher
//! injects inbox dispatches; a user must not be able to invoke the inbox through
//! the public RPC, or anyone could forge an inbound cross-zone delivery. The
//! inbox guest's caller-is-none assertion passes for a top-level user tx, so the
//! sequencer ingress guard is the only thing that stops this.

use std::net::SocketAddr;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use cross_zone_inbox_core::{
    CrossZoneMessage, Instruction, inbox_config_account_id, inbox_seen_shard_account_id,
};
use integration_tests::{
    config::{self, SequencerPartialConfig},
    setup::{setup_bedrock_node, setup_sequencer},
};
use lee::{
    PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use tokio::test;

#[test]
async fn user_origin_inbox_call_rejected() -> Result<()> {
    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to set up Bedrock node")?;
    let partial = SequencerPartialConfig::default();
    let channel = config::bedrock_channel_id();
    let (seq, _seq_home) = setup_sequencer(partial, bedrock_addr, vec![], channel, None)
        .await
        .context("Failed to set up sequencer")?;

    // A user hand-builds a top-level inbox Dispatch and submits it via RPC.
    let inbox_id = programs::cross_zone_inbox().id();
    let msg = CrossZoneMessage {
        src_zone: [2; 32],
        src_block_id: 1,
        src_tx_index: 0,
        src_program_id: [9; 8],
        target_program_id: programs::ping_receiver().id(),
        payload: vec![],
        l1_inclusion_witness: None,
    };
    let seen_id = inbox_seen_shard_account_id(inbox_id, &msg.src_zone, msg.src_block_id);
    let message = Message::try_new(
        inbox_id,
        vec![inbox_config_account_id(inbox_id), seen_id],
        vec![],
        Instruction::Dispatch(msg),
    )
    .expect("build dispatch message");
    let tx = LeeTransaction::Public(PublicTransaction::new(
        message,
        WitnessSet::from_raw_parts(vec![]),
    ));

    let result = sequencer_client(seq.addr())?.send_transaction(tx).await;
    let err = result.expect_err("the sequencer must reject a user-origin inbox call");
    assert!(
        err.to_string().contains("sequencer-only"),
        "rejection should cite the sequencer-only guard, got: {err}"
    );
    Ok(())
}

fn sequencer_client(addr: SocketAddr) -> Result<SequencerClient> {
    let url = config::addr_to_url(config::UrlProtocol::Http, addr)
        .context("Failed to build sequencer URL")?;
    SequencerClientBuilder::default()
        .build(url)
        .context("Failed to build sequencer client")
}
