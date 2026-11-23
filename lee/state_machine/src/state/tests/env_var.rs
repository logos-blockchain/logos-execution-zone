//! A program that decodes and uses a caller-supplied `env_var`, then has the loader assert it
//! against the target header (`test_guest_core::env_var`).

use program_loader_core::Message as LoaderMessage;
use test_guest_core::env_var::{EnvVarConfig, EnvVarConsumerMessage};

use super::*;
use crate::simulate_privacy_preserving_transaction;

const INPUT: u64 = 7;

struct Fixture {
    state: V03State,
    consumer_id: AccountId,
    target: AccountId,
    target_key: PrivateKey,
    segments: Vec<AccountId>,
    user: AccountId,
    user_key: PrivateKey,
}

impl Fixture {
    /// The target header holds `config(3)`.
    fn new() -> Self {
        let consumer = crate::test_methods::env_var_consumer();
        let consumer_id = AccountId::from_builtin_program(consumer.id());
        let mut state = V03State::new().with_programs([consumer]);
        let segments =
            force_insert_segment_chain(&mut state, crate::test_methods::scripted().elf(), 0x41);

        let target_key = PrivateKey::try_new([0x42; 32]).unwrap();
        let target = AccountId::from(&PublicKey::new_from_private_key(&target_key));
        let user_key = PrivateKey::try_new([0x43; 32]).unwrap();
        let user = AccountId::from(&PublicKey::new_from_private_key(&user_key));

        let mut fixture = Self {
            state,
            consumer_id,
            target,
            target_key,
            segments,
            user,
            user_key,
        };
        fixture.write_header(&LoaderMessage::CreateHeader {
            first_segment: fixture.segments[0],
            immutable: false,
            env_var: config(3),
        });
        fixture
    }

    fn write_header(&mut self, message: &LoaderMessage) {
        let to = Actor::new(self.target, PROGRAM_LOADER_ACCOUNT_ID);
        let nonce = self.state.get_account_by_id(self.target).nonce;
        let tx = public_tx(to, vec![to], vec![nonce], message, &[&self.target_key]);
        self.state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("the header write should succeed");
    }

    fn consumer(&self) -> Actor {
        Actor::new(self.user, self.consumer_id)
    }

    fn call_with(
        &mut self,
        header: AccountId,
        env_var: Vec<u8>,
        public_actors: Vec<Actor>,
    ) -> Result<Vec<TransactionEvent>, LeeError> {
        let nonce = self.state.get_account_by_id(self.user).nonce;
        let tx = public_tx(
            self.consumer(),
            public_actors,
            vec![nonce],
            EnvVarConsumerMessage::Use {
                header,
                env_var,
                input: INPUT,
            },
            &[&self.user_key],
        );
        self.state.transition_from_public_transaction(&tx, 1, 0)
    }

    fn call(
        &mut self,
        header: AccountId,
        env_var: Vec<u8>,
    ) -> Result<Vec<TransactionEvent>, LeeError> {
        let public_actors = vec![
            self.consumer(),
            Actor::new(header, PROGRAM_LOADER_ACCOUNT_ID),
        ];
        self.call_with(header, env_var, public_actors)
    }

    fn loader(&self) -> Actor {
        Actor::new(self.target, PROGRAM_LOADER_ACCOUNT_ID)
    }

    fn programs(&self) -> ProgramCatalog {
        ProgramCatalog::from([(self.consumer_id, crate::test_methods::env_var_consumer())])
    }

    /// The dry run reads the target's header as it is now.
    fn simulation(&self) -> Simulation {
        let header = self
            .state
            .loader_actor_state(self.target)
            .expect("the target holds a header")
            .clone();
        Simulation {
            public_actor_states: HashMap::from([(self.loader(), header)]),
            admitted_accounts: None,
        }
    }

    /// `to` runs `Use` against the target, alongside a fresh private account.
    fn proving_input(
        &self,
        to: Actor,
        env_var: Vec<u8>,
        public_actors: Vec<Actor>,
    ) -> ProvingInput {
        let message = EnvVarConsumerMessage::Use {
            header: self.target,
            env_var,
            input: INPUT,
        };
        ProvingInput {
            public_context: PublicExecutionContext::new(public_actors, []),
            private_witnesses: vec![init_witness(&test_private_account_keys_1())],
            ..proving_input(root(to, &message))
        }
    }

    fn private_consumer(&self) -> Actor {
        Actor::new(test_private_account_keys_1().account_id(), self.consumer_id)
    }

    fn prove(
        &self,
        input: ProvingInput,
        simulation: &Simulation,
    ) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
        execute_and_prove(
            input,
            simulation,
            &self.programs(),
            |_| SenderPresentation::Canonical,
            |_, _| false,
            no_seal,
        )
    }

    fn settle(&mut self, proved: (PrivacyPreservingCircuitOutput, Proof)) -> Result<(), LeeError> {
        self.state.transition_from_privacy_preserving_transaction(
            &private_tx(proved, vec![], &[]),
            1,
            0,
        )
    }

    fn consumer_state(&self) -> ActorState {
        self.state
            .get_account_by_id(self.user)
            .data
            .actor_state(self.consumer_id)
            .clone()
    }
}

fn config(multiplier: u64) -> Vec<u8> {
    borsh::to_vec(&EnvVarConfig { multiplier }).unwrap()
}

fn product(multiplier: u64) -> ActorState {
    ActorState::from(
        INPUT
            .checked_mul(multiplier)
            .unwrap()
            .to_le_bytes()
            .to_vec(),
    )
}

#[test]
fn a_matching_env_var_is_used_and_accepted() {
    let mut fixture = Fixture::new();

    fixture
        .call(fixture.target, config(3))
        .expect("a matching env_var should be accepted");

    assert_eq!(fixture.consumer_state(), product(3));
}

#[test]
fn a_mismatched_env_var_reverts_what_the_consumer_wrote() {
    let mut fixture = Fixture::new();

    let err = fixture
        .call(fixture.target, config(5))
        .expect_err("a mismatched env_var should be rejected");

    assert!(
        err.to_string().contains("the header's env_var differs"),
        "unexpected error: {err}"
    );
    assert_eq!(fixture.consumer_state(), ActorState::empty());
}

#[test]
fn an_undecodable_env_var_fails_in_the_consumer() {
    let mut fixture = Fixture::new();

    let err = fixture
        .call(fixture.target, vec![1, 2, 3])
        .expect_err("an undecodable env_var should be rejected");

    assert!(
        err.to_string()
            .contains("env_var must decode as EnvVarConfig"),
        "unexpected error: {err}"
    );
    assert_eq!(fixture.consumer_state(), ActorState::empty());
}

#[test]
fn a_segment_target_fails_the_assertion() {
    let mut fixture = Fixture::new();
    let segment = fixture.segments[0];

    let err = fixture
        .call(segment, config(3))
        .expect_err("a segment target should be rejected");

    assert!(
        err.to_string()
            .contains("AssertEnvVar target must hold a valid header"),
        "unexpected error: {err}"
    );
    assert_eq!(fixture.consumer_state(), ActorState::empty());
}

#[test]
fn a_target_with_no_header_fails_the_assertion() {
    let mut fixture = Fixture::new();
    let no_header = AccountId::new([0x44; 32]);
    fixture
        .state
        .force_insert_account(no_header, Account::funded(1));

    let err = fixture
        .call(no_header, config(3))
        .expect_err("a target with no header should be rejected");

    assert!(
        err.to_string()
            .contains("AssertEnvVar target must hold a valid header"),
        "unexpected error: {err}"
    );
    assert_eq!(fixture.consumer_state(), ActorState::empty());
}

#[test]
fn an_updated_env_var_replaces_the_old_one() {
    let mut fixture = Fixture::new();
    fixture.write_header(&LoaderMessage::UpdateHeader {
        first_segment: fixture.segments[0],
        immutable: false,
        env_var: config(4),
    });

    fixture
        .call(fixture.target, config(3))
        .expect_err("the old env_var should be rejected");
    fixture
        .call(fixture.target, config(4))
        .expect("the new env_var should be accepted");

    assert_eq!(fixture.consumer_state(), product(4));
}

#[test]
fn an_undeclared_target_is_rejected() {
    let mut fixture = Fixture::new();
    let public_actors = vec![fixture.consumer()];

    let result = fixture.call_with(fixture.target, config(3), public_actors);

    let loader = Actor::new(fixture.target, PROGRAM_LOADER_ACCOUNT_ID);
    assert!(matches!(
        execution_error(result),
        ExecutionError::UndeclaredActor { actor } if actor == loader
    ));
    assert_eq!(fixture.consumer_state(), ActorState::empty());
}

#[test]
fn a_private_consumer_with_a_matching_env_var_proves_and_settles() {
    let mut fixture = Fixture::new();
    let input = fixture.proving_input(
        fixture.private_consumer(),
        config(3),
        vec![fixture.loader()],
    );

    let proved = fixture
        .prove(input, &fixture.simulation())
        .expect("a matching env_var should prove");

    fixture
        .settle(proved)
        .expect("a matching env_var should settle");
}

#[test]
fn a_private_consumers_mismatched_env_var_fails_the_dry_run() {
    let fixture = Fixture::new();
    let input = fixture.proving_input(
        fixture.private_consumer(),
        config(5),
        vec![fixture.loader()],
    );

    let dry_run = simulate_privacy_preserving_transaction(
        &input,
        &fixture.simulation(),
        &fixture.programs(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
    );
    let err = dry_run.expect_err("a mismatched env_var should fail the dry run");
    assert!(
        err.to_string().contains("the header's env_var differs"),
        "unexpected error: {err}"
    );

    fixture
        .prove(input, &fixture.simulation())
        .expect_err("a mismatched env_var should not prove");
}

#[test]
fn an_env_var_changed_after_proving_fails_at_settlement() {
    let mut fixture = Fixture::new();
    let input = fixture.proving_input(
        fixture.private_consumer(),
        config(3),
        vec![fixture.loader()],
    );
    let proved = fixture
        .prove(input, &fixture.simulation())
        .expect("the env_var matches when proving");

    fixture.write_header(&LoaderMessage::UpdateHeader {
        first_segment: fixture.segments[0],
        immutable: false,
        env_var: config(4),
    });

    let err = fixture
        .settle(proved)
        .expect_err("a stale env_var should fail at settlement");
    assert!(
        err.to_string().contains("the header's env_var differs"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_private_consumers_undeclared_target_fails_the_dry_run() {
    let fixture = Fixture::new();
    let input = fixture.proving_input(fixture.private_consumer(), config(3), Vec::new());

    let result = fixture.prove(input, &fixture.simulation());

    let loader = fixture.loader();
    assert!(matches!(
        execution_error(result),
        ExecutionError::UndeclaredActor { actor } if actor == loader
    ));
}

#[test]
fn a_public_consumer_in_a_privacy_transaction_asserts_an_env_var() {
    let mut fixture = Fixture::new();
    let caller = AccountId::new([0x45; 32]);
    fixture
        .state
        .force_insert_account(caller, Account::funded(1));
    let consumer = Actor::new(caller, fixture.consumer_id);
    let input = fixture.proving_input(consumer, config(3), vec![consumer, fixture.loader()]);
    let mut simulation = fixture.simulation();
    simulation
        .public_actor_states
        .insert(consumer, ActorState::empty());

    let proved = fixture
        .prove(input, &simulation)
        .expect("a public consumer's env_var assertion should prove");
    fixture
        .settle(proved)
        .expect("a public consumer's env_var assertion should settle");

    assert_eq!(
        fixture
            .state
            .get_account_by_id(caller)
            .data
            .actor_state(fixture.consumer_id),
        &product(3)
    );
}
