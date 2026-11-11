use lee_core::{
    account::Actor,
    program::{ReceiveInput, Response, write_once},
};
use test_guest_core::chat::{
    ChatLog, ChatMessage, Delivery, EMITTER_MAGIC, ReceiverConfig, chat_log_account_id,
    chat_log_seed, receiver_config_account_id, receiver_config_seed,
};

lee_core::actor_entrypoint!(raw handle_message);

fn handle_message(input: &ReceiveInput) -> Response {
    let program = input.receiver.program_account_id;
    if input.receiver.account_id == program && input.from.is_some() {
        let delivery: Delivery = borsh::from_slice(&input.message).expect("a delivery decodes");
        return deliver(input, delivery);
    }
    let message: ChatMessage =
        borsh::from_slice(&input.message).expect("message must decode from borsh");
    match message {
        // Declaring the emission is the whole send: the watcher reads it off
        // this instruction. Top level only, since emissions are recognized only
        // at a transaction's top level.
        ChatMessage::Post { magic, .. } => {
            assert!(
                input.from.is_none(),
                "Post is a top-level instruction; a chained emission is never recognized"
            );
            assert!(magic == EMITTER_MAGIC, "a Post declares the emitter magic");
            Response::keep_state()
        }
        // The claim arrives at the program account, whose key only the deployer
        // holds, and is forwarded to the config PDA; a bare first write at the
        // PDA would be front-runnable in the mempool.
        ChatMessage::InitConfig(config) => {
            if input.receiver.account_id == program {
                assert!(
                    input.is_authorized,
                    "the deployer must authorize the receiver config claim"
                );
                Response::keep_state().send(
                    lee_core::program::SyncMessage::new(
                        Actor::new(receiver_config_account_id(program), program),
                        &ChatMessage::InitConfig(config),
                    )
                    .with_pda_seeds(vec![receiver_config_seed()]),
                )
            } else {
                assert!(
                    input.from_own_program(),
                    "the config is only claimed through the program account"
                );
                assert!(
                    input.receiver.account_id == receiver_config_account_id(program),
                    "the config is only written at the receiver config PDA"
                );
                Response::set_state(write_once(&input.pre_state, config.to_bytes()))
            }
        }
        ChatMessage::DeliverFrom {
            deliverer,
            src_zone,
            src_account_id,
            payload,
        } => {
            assert!(
                input.from_own_program(),
                "a delivery is only forwarded by this program's own account"
            );
            let cfg = ReceiverConfig::from_bytes(&input.pre_state)
                .expect("config account holds a receiver config");
            assert_eq!(
                deliverer, cfg.deliverer,
                "a delivery comes only from the authorized deliverer (the cross-zone inbox)"
            );
            assert!(
                cfg.authorizes(&src_zone, src_account_id),
                "a delivery comes only from a peer source this receiver authorizes"
            );
            Response::keep_state().send(
                lee_core::program::SyncMessage::new(
                    Actor::new(chat_log_account_id(program), program),
                    &ChatMessage::WriteLog {
                        src_zone,
                        text: payload,
                    },
                )
                .with_pda_seeds(vec![chat_log_seed()]),
            )
        }
        ChatMessage::WriteLog { src_zone, text } => {
            assert!(
                input.from_own_program(),
                "the log is only written by this program's config"
            );
            let mut log = ChatLog::from_bytes(&input.pre_state).expect("chat log decodes");
            log.push(src_zone, text);
            Response::set_state(log.to_bytes())
        }
    }
}

/// The program account forwards a delivery to the config, naming the program
/// that sent it; only the config can check it, since it holds the sources.
fn deliver(input: &ReceiveInput, delivery: Delivery) -> Response {
    let Delivery {
        src_zone,
        src_account_id,
        payload,
    } = delivery;
    let program = input.receiver.program_account_id;
    Response::keep_state().send_sync(
        Actor::new(receiver_config_account_id(program), program),
        &ChatMessage::DeliverFrom {
            deliverer: input
                .from
                .expect("a delivery has a sender")
                .program_account_id,
            src_zone,
            src_account_id,
            payload,
        },
    )
}
