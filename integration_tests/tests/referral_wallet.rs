#![expect(
    clippy::tests_outside_test_module,
    clippy::arithmetic_side_effects,
    reason = "We don't care about these in tests"
)]

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use bip39::Mnemonic;
use common::{
    HashType,
    block::{BedrockStatus, Block, BlockBody, BlockHeader},
    transaction::LeeTransaction,
};
use jsonrpsee::{
    core::async_trait,
    types::{ErrorObject, ErrorObjectOwned},
};
use key_protocol::key_management::secret_holders::SecretSpendingKey;
use lee::{Account, AccountId, ProgramId, ProgramShardSelector, V03State};
use lee_core::{
    BlockId, Commitment, CommitmentSetDigest, MembershipProof, account::Nonce, program::PdaSeed,
};
use referral_core::{
    Invitation, NodeId, ORACLE_ACCOUNT_ID, PROTOTYPE_ORACLE_SIGNING_KEY, State, StoredState,
    credit_account_id,
    ed25519_dalek::{Signature, Signer as _, SigningKey},
    ticket_account_id,
};
use sequencer_service_protocol::{
    ChannelId, CrossZoneDeadLetterReport, CrossZoneDeadLetterRequeue, FeeStateQuote,
};
use sequencer_service_rpc::RpcServer;
use tokio::test;
use wallet::{
    ExecutionFailureKind, WalletCore,
    config::{MultiSequencerClientConfig, SequencerConnectionData, WalletConfigOverrides},
    program_facades::referral,
    storage::referral::{OperationKind, PendingOperation, SubmissionStatus},
};

struct Ledger {
    state: V03State,
    height: BlockId,
    transactions: HashMap<HashType, (LeeTransaction, BlockId)>,
    blocks: BTreeMap<BlockId, Vec<LeeTransaction>>,
    swallow_responses: bool,
    reject_next: bool,
    settle_on_query: Option<(SettleTrigger, LeeTransaction)>,
    slow_block_id: bool,
    transaction_index: TransactionIndex,
}

enum TransactionIndex {
    Serving,
    Hidden,
    Unreachable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettleTrigger {
    Nonces,
    AccountView,
}

#[derive(Clone)]
struct InProcessSequencer {
    ledger: Arc<Mutex<Ledger>>,
}

#[async_trait]
impl RpcServer for InProcessSequencer {
    async fn send_transaction(&self, tx: LeeTransaction) -> Result<HashType, ErrorObjectOwned> {
        let hash = tx.hash();
        let mut ledger = self.ledger.lock().expect("ledger is not poisoned");
        if ledger.reject_next {
            ledger.reject_next = false;
            return Err(rpc_error("dropped before admission"));
        }
        apply(&mut ledger, tx).map_err(|err| rpc_error(&err))?;
        if ledger.swallow_responses {
            return Err(rpc_error("connection reset before the response arrived"));
        }
        Ok(hash)
    }

    async fn get_fee_state(&self) -> Result<FeeStateQuote, ErrorObjectOwned> {
        Ok(FeeStateQuote {
            height: self.ledger.lock().expect("ledger is not poisoned").height,
            base_fee_exec: 0,
            base_fee_stor: 0,
            next_base_fee_exec_floor: 0,
            next_base_fee_exec_ceiling: 0,
            next_base_fee_stor_floor: 0,
            next_base_fee_stor_ceiling: 0,
            max_gas_exec: u64::MAX,
            max_gas_stor: u64::MAX,
        })
    }

    async fn check_health(&self) -> Result<(), ErrorObjectOwned> {
        Ok(())
    }

    async fn get_block(&self, block_id: BlockId) -> Result<Option<Block>, ErrorObjectOwned> {
        let ledger = self.ledger.lock().expect("ledger is not poisoned");
        Ok((block_id <= ledger.height).then(|| {
            block_at(
                block_id,
                ledger.blocks.get(&block_id).cloned().unwrap_or_default(),
            )
        }))
    }

    async fn get_block_range(
        &self,
        start_block_id: BlockId,
        end_block_id: BlockId,
    ) -> Result<Vec<Block>, ErrorObjectOwned> {
        let ledger = self.ledger.lock().expect("ledger is not poisoned");
        Ok((start_block_id..=end_block_id.min(ledger.height))
            .map(|id| block_at(id, ledger.blocks.get(&id).cloned().unwrap_or_default()))
            .collect())
    }

    async fn get_last_block_id(&self) -> Result<BlockId, ErrorObjectOwned> {
        let (height, slow) = {
            let ledger = self.ledger.lock().expect("ledger is not poisoned");
            (ledger.height, ledger.slow_block_id)
        };
        if slow {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        Ok(height)
    }

    async fn get_account_balance(&self, account_id: AccountId) -> Result<u128, ErrorObjectOwned> {
        Ok(self
            .ledger
            .lock()
            .expect("ledger is not poisoned")
            .state
            .get_account_by_id(account_id)
            .data
            .balance()
            .unwrap_or_default())
    }

    async fn get_transaction(
        &self,
        tx_hash: HashType,
    ) -> Result<Option<(LeeTransaction, BlockId)>, ErrorObjectOwned> {
        let ledger = self.ledger.lock().expect("ledger is not poisoned");
        match ledger.transaction_index {
            TransactionIndex::Unreachable => Err(rpc_error("the transaction index is unreachable")),
            TransactionIndex::Hidden => Ok(None),
            TransactionIndex::Serving => Ok(ledger.transactions.get(&tx_hash).cloned()),
        }
    }

    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<Vec<Nonce>, ErrorObjectOwned> {
        let mut ledger = self.ledger.lock().expect("ledger is not poisoned");
        settle_on(&mut ledger, SettleTrigger::Nonces);
        Ok(account_ids
            .into_iter()
            .map(|id| ledger.state.get_account_by_id(id).nonce)
            .collect())
    }

    async fn get_account_view(
        &self,
        shard_selector: ProgramShardSelector,
    ) -> Result<Account, ErrorObjectOwned> {
        let mut ledger = self.ledger.lock().expect("ledger is not poisoned");
        settle_on(&mut ledger, SettleTrigger::AccountView);
        let account = ledger.state.get_account_by_id(shard_selector.account_id);
        Ok(Account {
            nonce: account.nonce,
            data: account.data.project([shard_selector.program_account_id]),
        })
    }

    async fn get_proofs_and_root(
        &self,
        commitments: Vec<Commitment>,
    ) -> Result<(Vec<Option<MembershipProof>>, CommitmentSetDigest), ErrorObjectOwned> {
        let ledger = self.ledger.lock().expect("ledger is not poisoned");
        Ok((
            commitments
                .iter()
                .map(|commitment| ledger.state.get_proof_for_commitment(commitment))
                .collect(),
            ledger.state.commitment_root(),
        ))
    }

    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned> {
        Ok(self
            .ledger
            .lock()
            .expect("ledger is not poisoned")
            .state
            .get_account_by_id(account_id))
    }

    async fn get_program_ids(&self) -> Result<BTreeMap<String, ProgramId>, ErrorObjectOwned> {
        Ok(BTreeMap::from([(
            "referral".to_owned(),
            programs::referral().id(),
        )]))
    }

    async fn get_channel_id(&self) -> Result<ChannelId, ErrorObjectOwned> {
        Err(rpc_error("cross-zone is out of scope for this harness"))
    }

    async fn get_cross_zone_dead_letters(
        &self,
    ) -> Result<CrossZoneDeadLetterReport, ErrorObjectOwned> {
        Err(rpc_error("cross-zone is out of scope for this harness"))
    }

    async fn requeue_cross_zone_dead_letter(
        &self,
        _message_key: HashType,
    ) -> Result<CrossZoneDeadLetterRequeue, ErrorObjectOwned> {
        Err(rpc_error("cross-zone is out of scope for this harness"))
    }
}

struct WalletHome {
    directory: tempfile::TempDir,
    overrides: WalletConfigOverrides,
}

impl WalletHome {
    fn paths(&self) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        (
            self.directory.path().join("config.json"),
            self.directory.path().join("storage.json"),
            self.directory.path().join("statistics.json"),
        )
    }

    async fn create(address: SocketAddr) -> (Self, WalletCore, Mnemonic) {
        Self::create_with(overrides(&[address])).await
    }

    async fn create_with(overrides: WalletConfigOverrides) -> (Self, WalletCore, Mnemonic) {
        let home = Self {
            directory: tempfile::tempdir().expect("a temp wallet home"),
            overrides,
        };
        let (config, storage, statistics) = home.paths();
        let (wallet, mnemonic) = WalletCore::new_init_storage(
            config,
            storage,
            statistics,
            Some(home.overrides.clone()),
            "test",
        )
        .await
        .expect("the wallet starts against the in-process sequencer");
        (home, wallet, mnemonic)
    }

    async fn restore(overrides: WalletConfigOverrides, mnemonic: &Mnemonic) -> (Self, WalletCore) {
        let (home, mut wallet, _fresh) = Self::create_with(overrides).await;
        wallet
            .restore_storage(mnemonic, "test")
            .expect("the wallet rebuilds its key trees from the mnemonic");
        wallet
            .store_persistent_data()
            .expect("the restored storage is persisted");
        (home, wallet)
    }

    async fn reopen(&self) -> WalletCore {
        let (config, storage, statistics) = self.paths();
        WalletCore::new_update_chain(config, storage, statistics, Some(self.overrides.clone()))
            .await
            .expect("the wallet reloads its persisted storage")
    }
}

struct Member {
    home: WalletHome,
    wallet: WalletCore,
    mnemonic: Mnemonic,
    key: SigningKey,
    node: NodeId,
    account: AccountId,
}

impl Member {
    fn facade(&mut self) -> referral::Referral<'_> {
        referral::Referral::new(&mut self.wallet, programs::referral(), program_account())
    }

    fn authorize(&mut self, referrer: Option<NodeId>) {
        let account = self.account;
        let node = self.node;
        let key = self.key.clone();
        let authorization = self
            .facade()
            .prepare_registration(account, node, referrer)
            .expect("a registration can be started");
        let signature = key.sign(&authorization.message()).to_bytes();
        self.facade()
            .attach_node_signature(account, signature)
            .expect("the node's signature is accepted");
    }

    async fn register(&mut self, referrer: Option<NodeId>) {
        self.authorize(referrer);
        let account = self.account;
        let reference = self.node.to_bytes();
        self.facade()
            .submit(reference, register(account))
            .await
            .expect("the registration is broadcast");
        assert_eq!(
            self.reconcile(reference).await,
            SubmissionStatus::Settled,
            "the registration settles on its effects"
        );
        self.sync().await;
    }

    fn restored_as(&self, home: WalletHome, wallet: WalletCore, account: AccountId) -> Self {
        Self {
            home,
            wallet,
            mnemonic: self.mnemonic.clone(),
            key: self.key.clone(),
            node: self.node,
            account,
        }
    }

    async fn restore(&self) -> Self {
        let (home, mut wallet) =
            WalletHome::restore(self.home.overrides.clone(), &self.mnemonic).await;
        wallet
            .storage_mut()
            .key_chain_mut()
            .generate_new_privacy_preserving_transaction_key_chain(None);
        let mut restored = self.restored_as(home, wallet, self.account);
        assert!(
            restored
                .wallet
                .storage()
                .key_chain()
                .private_account(self.account)
                .is_none(),
            "the seed alone does not re-derive the participant's random identifier"
        );
        restored.sync().await;
        assert!(
            restored
                .wallet
                .storage()
                .key_chain()
                .private_account(self.account)
                .is_some(),
            "the participant is rediscovered from the note that carries its identifier"
        );
        restored
    }

    async fn restore_with_a_new_participant(&self) -> Self {
        let (home, mut wallet) =
            WalletHome::restore(self.home.overrides.clone(), &self.mnemonic).await;
        let account = referral::Referral::new(&mut wallet, programs::referral(), program_account())
            .create_participant()
            .expect("a restored wallet starts a participant of its own");
        let mut restored = self.restored_as(home, wallet, account);
        restored.sync().await;
        restored
    }

    async fn sync(&mut self) {
        self.wallet.sync_to_latest_block().await.expect("syncs");
    }

    fn reward_balance(&mut self) -> u128 {
        let account = self.account;
        let State::Participant { reward_balance, .. } = self
            .facade()
            .state(account)
            .expect("the participant exists")
        else {
            panic!("not a participant");
        };
        reward_balance
    }

    async fn restart(&mut self) {
        self.wallet = self.home.reopen().await;
    }

    async fn submit(
        &mut self,
        reference: [u8; 32],
        source: AccountId,
        output_seed: Option<PdaSeed>,
    ) -> Result<(HashType, SubmissionStatus), ExecutionFailureKind> {
        let account = self.account;
        self.facade()
            .submit(reference, collect(account, source, output_seed))
            .await
    }

    async fn reconcile(&mut self, reference: [u8; 32]) -> SubmissionStatus {
        self.facade()
            .reconcile(reference)
            .await
            .expect("the wallet reconciles against what the sequencers serve")
    }

    fn status(&mut self, reference: [u8; 32]) -> Option<SubmissionStatus> {
        self.facade().operation_status(reference)
    }

    fn recorded(&self, reference: [u8; 32]) -> PendingOperation {
        self.wallet
            .storage()
            .referral()
            .operation(reference)
            .expect("the operation was persisted before it was broadcast")
            .clone()
    }

    fn invitation(&mut self) -> Invitation {
        let account = self.account;
        let node = self.node;
        self.facade()
            .invitation(account, node)
            .expect("an invitation can be built")
    }

    fn import(&mut self, invitation: Invitation) {
        let account = self.account;
        self.facade()
            .import_invitation(account, invitation)
            .expect("the referrer's invitation is imported");
    }

    fn credit(&mut self, seed: PdaSeed) -> AccountId {
        let account = self.account;
        let descriptor = self
            .facade()
            .descriptor(account)
            .expect("the participant's keys are known");
        credit_account_id(program_account(), &seed, &descriptor.npk, &descriptor.vpk)
    }

    fn reserve(&mut self) -> PdaSeed {
        let account = self.account;
        self.facade()
            .reserve_credit(account)
            .expect("a credit seed is reserved before submitting")
    }
}

struct Scenario {
    ledger: Arc<Mutex<Ledger>>,
    lagging: Option<Arc<Mutex<Ledger>>>,
    oracle: WalletCore,
    bob: Member,
    source: AccountId,
    _oracle_home: WalletHome,
    _handles: Vec<jsonrpsee::server::ServerHandle>,
}

impl Scenario {
    async fn root(amount: u128) -> Self {
        Self::build(amount, false).await
    }

    async fn failover(amount: u128) -> Self {
        Self::build(amount, true).await
    }

    async fn build(amount: u128, failover: bool) -> Self {
        let (ledger, address, handle) = start_sequencer().await;
        let mut handles = vec![handle];
        let mut addresses = vec![address];
        let lagging = if failover {
            let (lagging, lagging_address, lagging_handle) = start_sequencer().await;
            lagging
                .lock()
                .expect("ledger is not poisoned")
                .slow_block_id = true;
            handles.push(lagging_handle);
            addresses.push(lagging_address);
            Some(lagging)
        } else {
            None
        };

        let config = overrides(&addresses);
        let (oracle_home, mut oracle, _mnemonic) = WalletHome::create_with(config.clone()).await;
        import_oracle(&mut oracle);
        let mut bob = member_with(config, 1).await;

        oracle_grant(&mut oracle, [0x20; 32], bob.node, amount).await;
        bob.register(None).await;

        Self {
            ledger,
            lagging,
            oracle,
            source: ticket_account_id(program_account(), bob.node),
            bob,
            _oracle_home: oracle_home,
            _handles: handles,
        }
    }

    async fn collect(
        &mut self,
        reference: [u8; 32],
        output_seed: Option<PdaSeed>,
    ) -> Result<(HashType, SubmissionStatus), ExecutionFailureKind> {
        let source = self.source;
        self.bob.submit(reference, source, output_seed).await
    }

    async fn grant(&mut self, reference: [u8; 32], amount: u128) {
        oracle_grant(&mut self.oracle, reference, self.bob.node, amount).await;
    }

    fn tickets(&self) -> u128 {
        ticket_amount(&self.ledger, self.bob.node)
    }

    fn swallow_responses(&self, swallow: bool) {
        self.ledger
            .lock()
            .expect("ledger is not poisoned")
            .swallow_responses = swallow;
    }

    fn reject_next(&self) {
        self.ledger
            .lock()
            .expect("ledger is not poisoned")
            .reject_next = true;
    }
}

fn apply(ledger: &mut Ledger, tx: LeeTransaction) -> Result<(), String> {
    let hash = tx.hash();
    let block = ledger.height + 1;
    match &tx {
        LeeTransaction::Public(public) => ledger
            .state
            .transition_from_public_transaction(public, block, 0)
            .map(|_events| ()),
        LeeTransaction::PrivacyPreserving(private) => ledger
            .state
            .transition_from_privacy_preserving_transaction(private, block, 0)
            .map(|_events| ()),
    }
    .map_err(|err| format!("rejected: {err}"))?;

    ledger.height = block;
    ledger.transactions.insert(hash, (tx.clone(), block));
    ledger.blocks.insert(block, vec![tx]);
    Ok(())
}

fn settle_on(ledger: &mut Ledger, trigger: SettleTrigger) {
    if let Some((_trigger, pending)) = ledger.settle_on_query.take_if(|(at, _tx)| *at == trigger) {
        apply(ledger, pending).expect("the pending transaction applies");
    }
}

fn rpc_error(message: &str) -> ErrorObjectOwned {
    ErrorObject::owned(-32000, message.to_owned(), None::<()>)
}

fn block_at(block_id: BlockId, transactions: Vec<LeeTransaction>) -> Block {
    let producer_key = lee::PrivateKey::try_new([0x5A; 32]).expect("the producer key parses");
    let producer = lee::PublicKey::new_from_private_key(&producer_key);
    let mut block = Block {
        header: BlockHeader {
            block_id,
            prev_block_hash: HashType([0; 32]),
            hash: HashType([0; 32]),
            timestamp: 0,
            producer,
            signature: lee::Signature::new(&producer_key, &[0; 32]),
        },
        body: BlockBody { transactions },
        bedrock_status: BedrockStatus::Finalized,
    };
    block.header.hash = block.recompute_hash();
    block.header.signature = lee::Signature::new(&producer_key, &block.header.hash.0);
    block
}

fn program_account() -> AccountId {
    programs::referral().id().into()
}

fn node(seed: u8) -> (SigningKey, NodeId) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = NodeId::new(key.verifying_key().to_bytes());
    (key, id)
}

async fn start_sequencer() -> (
    Arc<Mutex<Ledger>>,
    SocketAddr,
    jsonrpsee::server::ServerHandle,
) {
    let ledger = Arc::new(Mutex::new(Ledger {
        state: V03State::new()
            .with_public_accounts([(ORACLE_ACCOUNT_ID, Account::funded(1_000_000_000))])
            .with_programs([programs::referral()]),
        height: 1,
        transactions: HashMap::new(),
        blocks: BTreeMap::new(),
        swallow_responses: false,
        reject_next: false,
        settle_on_query: None,
        slow_block_id: false,
        transaction_index: TransactionIndex::Serving,
    }));

    let server = jsonrpsee::server::Server::builder()
        .build("127.0.0.1:0")
        .await
        .expect("the in-process sequencer binds");
    let address = server.local_addr().expect("the server has an address");
    let handle = server.start(
        InProcessSequencer {
            ledger: Arc::clone(&ledger),
        }
        .into_rpc(),
    );

    (ledger, address, handle)
}

fn overrides(addresses: &[SocketAddr]) -> WalletConfigOverrides {
    WalletConfigOverrides {
        sequencers: Some(
            addresses
                .iter()
                .map(|address| SequencerConnectionData {
                    sequencer_addr: format!("http://{address}")
                        .parse()
                        .expect("the sequencer address is a URL"),
                    basic_auth: None,
                })
                .collect(),
        ),
        multi_sequencer_client_config: (addresses.len() > 1).then_some(
            MultiSequencerClientConfig {
                distribution_limit: 2,
                calibration_limit: 3,
            },
        ),
        ..WalletConfigOverrides::default()
    }
}

fn import_oracle(wallet: &mut WalletCore) {
    wallet
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(
            lee::PrivateKey::try_new(PROTOTYPE_ORACLE_SIGNING_KEY).expect("the oracle key parses"),
        );
    wallet
        .store_persistent_data()
        .expect("the oracle key is persisted");
}

fn stored_state(ledger: &Arc<Mutex<Ledger>>, account_id: AccountId) -> Option<State> {
    let ledger = ledger.lock().expect("ledger is not poisoned");
    let account = ledger.state.get_account_by_id(account_id);
    StoredState::decode(account.data.shard(program_account())).map(|stored| stored.state)
}

fn ticket_amount(ledger: &Arc<Mutex<Ledger>>, node: NodeId) -> u128 {
    match stored_state(ledger, ticket_account_id(program_account(), node)) {
        None => 0,
        Some(State::Credit { amount, .. }) => amount,
        Some(other @ (State::Registry(_) | State::Participant { .. })) => {
            panic!("not a ticket account: {other:?}")
        }
    }
}

const fn collect(
    participant: AccountId,
    source: AccountId,
    output_seed: Option<PdaSeed>,
) -> OperationKind {
    OperationKind::Collect {
        participant,
        source,
        output_seed,
    }
}

const fn grant(node: NodeId, amount: u128) -> OperationKind {
    OperationKind::Grant { node, amount }
}

const fn register(participant: AccountId) -> OperationKind {
    OperationKind::Register { participant }
}

fn foreign_invitation(seed: u8, node: NodeId) -> Invitation {
    let holder = SecretSpendingKey([seed; 32]).produce_private_key_holder(None);
    Invitation::new(
        program_account(),
        node,
        holder.generate_nullifier_public_key(),
        holder.generate_viewing_public_key(),
    )
}

fn oracle_facade(oracle: &mut WalletCore) -> referral::Referral<'_> {
    referral::Referral::new(oracle, programs::referral(), program_account())
}

async fn oracle_submit(
    oracle: &mut WalletCore,
    reference: [u8; 32],
    operation: OperationKind,
) -> Result<(HashType, SubmissionStatus), ExecutionFailureKind> {
    oracle_facade(oracle).submit(reference, operation).await
}

async fn oracle_grant(oracle: &mut WalletCore, reference: [u8; 32], node: NodeId, amount: u128) {
    oracle_submit(oracle, reference, grant(node, amount))
        .await
        .expect("the node is granted its tickets");
}

async fn member(address: SocketAddr, node_seed: u8) -> Member {
    member_with(overrides(&[address]), node_seed).await
}

async fn member_with(overrides: WalletConfigOverrides, node_seed: u8) -> Member {
    let (home, mut wallet, mnemonic) = WalletHome::create_with(overrides).await;
    let (key, node) = node(node_seed);
    let account = referral::Referral::new(&mut wallet, programs::referral(), program_account())
        .create_participant()
        .expect("the wallet creates a participant with a private identifier");
    Member {
        home,
        wallet,
        mnemonic,
        key,
        node,
        account,
    }
}

async fn oracle_wallet(address: SocketAddr) -> (WalletHome, WalletCore) {
    let (home, mut wallet, _mnemonic) = WalletHome::create(address).await;
    import_oracle(&mut wallet);
    (home, wallet)
}

#[test]
async fn the_worked_example_pays_five_to_bob_alice_and_carol_through_real_wallets() {
    let (ledger, address, _handle) = start_sequencer().await;
    let (_oracle_home, mut oracle) = oracle_wallet(address).await;
    let mut bob = member(address, 1).await;
    let mut alice = member(address, 2).await;
    let mut carol = member(address, 3).await;

    oracle_grant(&mut oracle, [0x20; 32], bob.node, 5).await;
    assert_eq!(ticket_amount(&ledger, bob.node), 5);

    let alice_invitation = alice.invitation();
    let carol_invitation = carol.invitation();
    bob.import(alice_invitation);
    alice.import(carol_invitation.clone());

    let abandoned = carol.account;
    let carol_node = carol.node;
    let mut carol = carol.restore_with_a_new_participant().await;
    let carol_account = carol.account;
    assert_ne!(
        carol_account, abandoned,
        "an identifier that was never broadcast is not recoverable from the seed"
    );
    assert!(
        carol.facade().intent(carol_account).is_none(),
        "a restore recovers notes, not the wallet-local intents that preceded them"
    );

    carol.register(None).await;
    alice.register(Some(carol_node)).await;
    bob.register(Some(alice.node)).await;

    let bob_source = ticket_account_id(program_account(), bob.node);
    let alice_seed = bob.reserve();
    bob.submit([5; 32], bob_source, Some(alice_seed))
        .await
        .expect("Bob's first collect settles");

    assert_eq!(ticket_amount(&ledger, bob.node), 0);
    bob.sync().await;
    assert_eq!(bob.reward_balance(), 5);

    alice.sync().await;
    let alice_account = alice.account;
    let alice_node = alice.node;
    let incoming = alice.credit(alice_seed);
    assert_eq!(
        alice
            .facade()
            .state(incoming)
            .expect("Alice discovers the credit her registration entitled her to"),
        State::Credit {
            recipient_node: alice_node,
            amount: 5,
        }
    );
    assert_eq!(
        alice
            .facade()
            .state(alice_account)
            .expect("Alice registered before the credit arrived"),
        State::Participant {
            node: alice_node,
            referrer: Some(carol_node),
            reward_balance: 0,
        }
    );

    let carol_seed = alice.reserve();
    alice
        .submit([6; 32], incoming, Some(carol_seed))
        .await
        .expect("Alice's first collect settles");
    alice.sync().await;
    assert_eq!(alice.reward_balance(), 5);
    assert_eq!(
        ticket_amount(&ledger, alice.node),
        0,
        "Alice never needed a ticket account"
    );

    carol.sync().await;
    let forwarded = carol.credit(carol_seed);
    assert_eq!(
        carol
            .facade()
            .state(forwarded)
            .expect("a wallet restored from the seed phrase alone discovers the credit"),
        State::Credit {
            recipient_node: carol_node,
            amount: 5,
        }
    );

    carol
        .submit([7; 32], forwarded, None)
        .await
        .expect("Carol's first collect settles");
    carol.sync().await;
    assert_eq!(carol.reward_balance(), 5);

    alice.facade().reconcile([6; 32]).await.expect("reconciles");
    let settled = alice
        .facade()
        .intent(alice_account)
        .expect("the intent survives")
        .clone();
    assert!(
        alice.facade().pending_registration(alice_account).is_none(),
        "the registration that preceded the collection settled with its own operation"
    );
    assert!(
        settled.pending_credits.is_empty(),
        "and the collection cleared the credit seed it accounted for"
    );
    assert!(
        settled.invitation.is_some(),
        "while the referrer's invitation survives the cleanup"
    );

    let mut recovered = alice.restore().await;
    assert_eq!(recovered.reward_balance(), 5);
    assert!(
        recovered.facade().intent(alice_account).is_none(),
        "the reward survives on the chain while the intent that earned it stays wallet-local"
    );

    oracle_grant(&mut oracle, [8; 32], bob.node, 5).await;
    let second_seed = bob.reserve();
    bob.submit([9; 32], bob_source, Some(second_seed))
        .await
        .expect("Bob collects his second grant for the same referrer");
    recovered.sync().await;

    let onward_seed = recovered.reserve();
    let second_source = recovered.credit(second_seed);
    assert!(
        recovered
            .submit([10; 32], second_source, Some(onward_seed))
            .await
            .is_err(),
        "a seed-restored wallet cannot deliver onwards without the referrer's invitation"
    );
    assert_eq!(
        recovered.status([10; 32]),
        None,
        "the refused collection is never recorded"
    );

    recovered
        .facade()
        .import_invitation(alice_account, carol_invitation)
        .expect("the invitation is reimported for the recorded deployment and parent");
    recovered
        .submit([10; 32], second_source, Some(onward_seed))
        .await
        .expect("the reimported invitation restores onward delivery");
    recovered.sync().await;
    assert_eq!(recovered.reward_balance(), 10);

    let mut reopened = recovered.home.reopen().await;
    let restarted = referral::Referral::new(&mut reopened, programs::referral(), program_account());
    let kept = restarted
        .intent(alice_account)
        .expect("the recovered intent was persisted before the seed was returned");
    assert_eq!(kept.pending_credits, vec![onward_seed]);
    assert!(kept.invitation.is_some());
    assert!(
        restarted.pending_registration(alice_account).is_none(),
        "reserving against a registered participant needs no new node authorization"
    );
}

#[test]
async fn registration_bookkeeping_resumes_refuses_conflicts_and_survives_a_restart() {
    let (_ledger, address, _handle) = start_sequencer().await;
    let mut bob = member(address, 1).await;
    let mut alice = member(address, 2).await;
    let (_carol_key, carol_node) = node(3);
    let account = bob.account;
    let bob_node = bob.node;

    let authorization = bob
        .facade()
        .prepare_registration(account, bob_node, None)
        .expect("a registration can be started");
    let signature = bob.key.sign(&authorization.message()).to_bytes();
    bob.facade()
        .attach_node_signature(account, signature)
        .expect("the node's signature is accepted");

    let resumed = bob
        .facade()
        .prepare_registration(account, bob_node, None)
        .expect("the same configuration resumes");
    assert_eq!(resumed.message(), authorization.message());
    assert!(bob.facade().pending_registration(account).is_some());
    assert!(
        bob.facade()
            .prepare_registration(account, alice.node, None)
            .is_err(),
        "a conflicting configuration is rejected"
    );

    assert!(
        referral::Referral::new(
            &mut bob.wallet,
            programs::referral(),
            AccountId::new([0xAB; 32])
        )
        .prepare_registration(account, bob_node, None)
        .is_err(),
        "another deployment with the same node is a conflict"
    );
    let kept = bob
        .facade()
        .pending_registration(account)
        .cloned()
        .expect("the original registration survives");
    assert_eq!(kept.node, bob_node);
    assert_eq!(kept.signature, Some(Signature::from_bytes(&signature)));
    assert_eq!(
        bob.facade()
            .intent(account)
            .expect("the intent survives")
            .program_account,
        program_account()
    );

    let alice_account = alice.account;
    let alice_node = alice.node;
    alice.import(foreign_invitation(0x44, carol_node));
    alice
        .facade()
        .prepare_registration(alice_account, alice_node, Some(carol_node))
        .expect("the imported invitation admits its node as the referrer");
    let bob_invitation = bob.invitation();
    assert!(
        alice
            .facade()
            .import_invitation(alice_account, bob_invitation)
            .is_err(),
        "an invitation from another node cannot replace the recorded referrer"
    );
    assert!(
        alice
            .facade()
            .prepare_registration(alice_account, alice_node, Some(bob_node))
            .is_err(),
        "and a registration for a referrer without an invitation is refused"
    );

    bob.restart().await;
    let survived = bob
        .facade()
        .pending_registration(account)
        .cloned()
        .expect("the registration survives a restart");
    assert_eq!(survived.node, bob_node);
    assert_eq!(survived.signature, Some(Signature::from_bytes(&signature)));

    bob.register(None).await;
    assert!(
        bob.facade()
            .prepare_registration(account, bob_node, None)
            .is_err(),
        "a registered participant refuses a second registration"
    );
    let mut twin = member(address, 1).await;
    let twin_account = twin.account;
    twin.authorize(None);
    assert!(
        twin.facade()
            .submit(bob_node.to_bytes(), register(twin_account))
            .await
            .is_err(),
        "a fresh participant for a node the registry already holds is refused when its registration is built"
    );
    assert_eq!(
        twin.status(bob_node.to_bytes()),
        None,
        "the refused registration is never recorded"
    );
}

#[test]
async fn a_grant_included_with_an_unobservable_effect_is_replaced_once_its_failure_is_recorded() {
    let (ledger, address, _handle) = start_sequencer().await;
    let (home, mut oracle) = oracle_wallet(address).await;
    let (_bob_key, bob_node) = node(1);
    let reference = [0xC1; 32];

    ledger
        .lock()
        .expect("ledger is not poisoned")
        .swallow_responses = true;
    assert!(
        oracle_submit(&mut oracle, reference, grant(bob_node, 5))
            .await
            .is_err(),
        "the caller sees a failure"
    );
    assert_eq!(ticket_amount(&ledger, bob_node), 5);
    ledger
        .lock()
        .expect("ledger is not poisoned")
        .swallow_responses = false;

    drop(oracle);
    let mut retried = home.reopen().await;
    let mut facade = oracle_facade(&mut retried);
    assert_eq!(
        facade.operation_status(reference),
        Some(SubmissionStatus::Pending)
    );

    let (hash, status) = facade
        .submit(reference, grant(bob_node, 5))
        .await
        .expect("the retry resolves");
    assert_eq!(status, SubmissionStatus::Included);
    assert_eq!(ticket_amount(&ledger, bob_node), 5);

    let (repeated, repeated_status) = facade
        .submit(reference, grant(bob_node, 5))
        .await
        .expect("an included operation is not retried on its own");
    assert_eq!(repeated, hash);
    assert_eq!(repeated_status, status);
    assert_eq!(ticket_amount(&ledger, bob_node), 5);

    assert_eq!(
        facade
            .record_failed_outcome(reference)
            .expect("an operator can record the outcome this interface cannot observe"),
        SubmissionStatus::Rejected
    );
    facade
        .submit(reference, grant(bob_node, 5))
        .await
        .expect("only then is a replacement authorized");
    assert_eq!(ticket_amount(&ledger, bob_node), 10);
}

#[test]
async fn a_grant_dropped_before_admission_is_seen_or_replaced_exactly_once() {
    let (ledger, address, _handle) = start_sequencer().await;
    let (_home, mut oracle) = oracle_wallet(address).await;
    let (_bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let landed = [0xD0; 32];
    let superseded = [0xD1; 32];

    ledger.lock().expect("ledger is not poisoned").reject_next = true;
    assert!(
        oracle_submit(&mut oracle, landed, grant(bob_node, 5))
            .await
            .is_err(),
        "the first attempt is dropped before admission"
    );
    assert_eq!(ticket_amount(&ledger, bob_node), 0);

    let recorded = oracle
        .storage()
        .referral()
        .operation(landed)
        .expect("the signed transaction was persisted")
        .transaction
        .clone();
    ledger
        .lock()
        .expect("ledger is not poisoned")
        .settle_on_query = Some((SettleTrigger::Nonces, recorded));

    let (_hash, status) = oracle_submit(&mut oracle, landed, grant(bob_node, 5))
        .await
        .expect("the retry resolves");
    assert!(
        status == SubmissionStatus::Included,
        "a transaction that lands between the two reads is seen, not replaced, got {status:?}"
    );
    assert_eq!(
        ticket_amount(&ledger, bob_node),
        5,
        "the grant issued exactly once"
    );

    ledger.lock().expect("ledger is not poisoned").reject_next = true;
    assert!(
        oracle_submit(&mut oracle, superseded, grant(bob_node, 5))
            .await
            .is_err(),
        "the replacement's first attempt is dropped before admission too"
    );

    oracle_submit(&mut oracle, [0xD2; 32], grant(alice_node, 5))
        .await
        .expect("another oracle transaction consumes the nonce");

    let mut facade = oracle_facade(&mut oracle);
    assert_eq!(
        facade.reconcile(superseded).await.expect("reconciles"),
        SubmissionStatus::Rejected
    );
    let (_replacement, replacement_status) = facade
        .submit(superseded, grant(bob_node, 5))
        .await
        .expect("a resolved rejection allows one replacement");
    assert_eq!(replacement_status, SubmissionStatus::Pending);
    assert_eq!(
        ticket_amount(&ledger, bob_node),
        10,
        "the replacement issued exactly once"
    );
}

#[test]
async fn a_submission_that_cannot_be_persisted_is_never_broadcast() {
    let (ledger, address, _handle) = start_sequencer().await;
    let (home, mut oracle) = oracle_wallet(address).await;
    let (_bob_key, bob_node) = node(1);
    let reference = [0xE1; 32];

    let (_config, storage, _statistics) = home.paths();
    std::fs::remove_file(&storage).expect("the storage file exists");
    std::fs::create_dir_all(&storage).expect("a directory now blocks the storage path");

    let mut facade = oracle_facade(&mut oracle);
    assert!(
        facade.submit(reference, grant(bob_node, 5)).await.is_err(),
        "a submission that cannot be recorded fails"
    );
    assert_eq!(facade.operation_status(reference), None);
    assert_eq!(ticket_amount(&ledger, bob_node), 0);
}

#[test]
async fn a_private_collect_settles_on_its_effects_when_its_history_is_lost() {
    let mut scenario = Scenario::root(5).await;
    let account = scenario.bob.account;
    let lost = [0xF1; 32];
    let hidden = [0xF5; 32];

    scenario.swallow_responses(true);
    assert!(
        scenario.collect(lost, None).await.is_err(),
        "the caller never learns the collection landed"
    );
    assert_eq!(scenario.tickets(), 0, "it did land");
    scenario.swallow_responses(false);

    scenario.bob.restart().await;
    let (_hash, status) = scenario
        .collect(lost, None)
        .await
        .expect("the retry resolves");
    assert!(
        status == SubmissionStatus::Settled,
        "a private operation's output commitment proves the effects applied, got {status:?}"
    );
    assert_eq!(scenario.tickets(), 0);
    assert!(
        scenario
            .bob
            .facade()
            .pending_registration(account)
            .is_none(),
        "a collect carries no registration material"
    );
    scenario.bob.sync().await;

    scenario.grant([0x30; 32], 7).await;
    scenario.reject_next();
    assert!(
        scenario.collect(hidden, None).await.is_err(),
        "the caller never learns what became of the second collect"
    );
    assert_eq!(scenario.tickets(), 7);

    let recorded = scenario.bob.recorded(hidden).transaction;
    {
        let mut ledger = scenario.ledger.lock().expect("ledger is not poisoned");
        ledger.settle_on_query = Some((SettleTrigger::AccountView, recorded));
        ledger.transaction_index = TransactionIndex::Hidden;
    }
    assert_eq!(
        scenario.bob.reconcile(hidden).await,
        SubmissionStatus::Settled,
        "a collection that lands while the ticket account it pinned is read has succeeded, not \
         been superseded"
    );

    scenario.grant([0x31; 32], 9).await;
    let (_answered, answered_status) = scenario
        .collect(hidden, None)
        .await
        .expect("a settled operation is answered, not rebuilt");
    assert_eq!(answered_status, SubmissionStatus::Settled);
    assert_eq!(
        scenario.tickets(),
        9,
        "the later grant is untouched, so no replacement was built"
    );
    scenario.bob.sync().await;
    assert_eq!(scenario.bob.reward_balance(), 12);
}

#[test]
async fn a_stale_private_collect_is_rebuilt_after_its_pinned_state_moves() {
    let mut scenario = Scenario::root(5).await;
    let first = [0xF2; 32];
    let second = [0xC6; 32];

    scenario.reject_next();
    assert!(
        scenario.collect(first, None).await.is_err(),
        "the proof never reaches a block"
    );
    assert_eq!(scenario.tickets(), 5);

    assert!(
        scenario.collect(second, None).await.is_err(),
        "a second reference against the same participant state is refused"
    );
    assert_eq!(
        scenario.bob.status(second),
        None,
        "the refused operation is never recorded"
    );
    assert_eq!(
        scenario.bob.status(first),
        Some(SubmissionStatus::Pending),
        "the unresolved operation is left as it was"
    );
    assert_eq!(scenario.tickets(), 5, "no second proof reached the chain");

    scenario.grant([0x32; 32], 3).await;
    assert_eq!(scenario.tickets(), 8);

    let LeeTransaction::PrivacyPreserving(stale) = scenario.bob.recorded(first).transaction else {
        panic!("a collection is a privacy preserving transaction");
    };
    assert!(
        scenario
            .bob
            .wallet
            .submit_privacy_preserving_transaction(stale)
            .await
            .is_err(),
        "a proof pinned to a superseded ticket pre-state must not settle"
    );
    assert_eq!(scenario.tickets(), 8, "the rejected proof moved nothing");

    let (_hash, status) = scenario
        .collect(first, None)
        .await
        .expect("the retry rebuilds against the current state");
    assert_eq!(
        status,
        SubmissionStatus::Pending,
        "the stale proof is abandoned and a fresh one submitted"
    );
    assert_eq!(
        scenario.tickets(),
        0,
        "the replacement drained the then-current balance once"
    );
    scenario.bob.sync().await;
    assert_eq!(scenario.bob.reward_balance(), 8);
}

#[test]
async fn a_two_sequencer_failover_resolves_a_lagging_collect_and_a_grant_probe() {
    let mut scenario = Scenario::failover(10).await;
    let lagging = Arc::clone(
        scenario
            .lagging
            .as_ref()
            .expect("the failover scenario starts a lagging sequencer"),
    );
    let node_id = scenario.bob.node;
    let first = [0xF6; 32];
    let second = [0xF7; 32];
    let probe = [0xB7; 32];

    scenario
        .collect(first, None)
        .await
        .expect("Bob's first collect settles on both sequencers");
    scenario.bob.sync().await;
    assert_eq!(
        scenario.bob.reconcile(first).await,
        SubmissionStatus::Settled
    );
    assert_eq!(ticket_amount(&lagging, node_id), 0);

    scenario.grant([0x33; 32], 6).await;
    scenario.swallow_responses(true);
    lagging.lock().expect("ledger is not poisoned").reject_next = true;
    assert!(
        scenario.collect(second, None).await.is_err(),
        "the caller never learns the helm applied the second collect"
    );
    assert_eq!(scenario.tickets(), 0);
    assert_eq!(
        ticket_amount(&lagging, node_id),
        6,
        "the lagging sequencer refused the same collection"
    );

    scenario.swallow_responses(false);
    scenario.bob.sync().await;
    scenario
        .ledger
        .lock()
        .expect("ledger is not poisoned")
        .transaction_index = TransactionIndex::Unreachable;

    assert_eq!(
        scenario.bob.reconcile(second).await,
        SubmissionStatus::Pending,
        "a node that has not seen every block this wallet scanned cannot witness a competing spend"
    );
    assert_eq!(
        scenario.tickets(),
        0,
        "the second collection consumed the whole grant exactly once"
    );
    assert_eq!(scenario.bob.reward_balance(), 16);

    scenario.swallow_responses(true);
    lagging.lock().expect("ledger is not poisoned").reject_next = true;
    assert!(
        oracle_submit(&mut scenario.oracle, probe, grant(node_id, 5))
            .await
            .is_err(),
        "the caller never learns the helm applied the grant"
    );
    assert_eq!(scenario.tickets(), 5);
    assert_eq!(
        ticket_amount(&lagging, node_id),
        6,
        "the lagging sequencer refused the same grant"
    );

    scenario.swallow_responses(false);
    let (_hash, status) = oracle_submit(&mut scenario.oracle, probe, grant(node_id, 5))
        .await
        .expect("the retry resolves");
    assert_eq!(
        status,
        SubmissionStatus::Pending,
        "the whole probe fails over, so the absent transaction is read beside the nonce that \
         belongs to it"
    );
    assert_eq!(
        scenario.tickets(),
        5,
        "the grant issued exactly once on the helm"
    );
}

#[test]
async fn a_collect_a_competing_wallet_overtook_is_rejected_and_rebuilt_exactly_once() {
    let (ledger, address, _handle) = start_sequencer().await;
    let (_oracle_home, mut oracle) = oracle_wallet(address).await;
    let mut bob = member(address, 1).await;
    let mut alice = member(address, 2).await;
    let mut carol = member(address, 3).await;
    let carol_invitation = foreign_invitation(0x44, carol.node);
    let first = [0xCB; 32];
    let second = [0xCC; 32];

    carol.register(None).await;
    alice.import(carol_invitation.clone());
    alice.register(Some(carol.node)).await;
    bob.import(alice.invitation());
    bob.register(Some(alice.node)).await;
    oracle_grant(&mut oracle, [0x20; 32], bob.node, 5).await;

    let bob_source = ticket_account_id(program_account(), bob.node);
    let first_seed = bob.reserve();
    bob.submit([4; 32], bob_source, Some(first_seed))
        .await
        .expect("Bob's first collect settles");
    bob.sync().await;

    alice.sync().await;
    let alice_account = alice.account;
    let first_source = alice.credit(first_seed);
    let first_output = alice.reserve();
    alice
        .submit(first, first_source, Some(first_output))
        .await
        .expect("Alice's first collect settles");
    alice.sync().await;
    assert_eq!(alice.reward_balance(), 5);

    oracle_grant(&mut oracle, [5; 32], bob.node, 5).await;
    let second_seed = bob.reserve();
    bob.submit([6; 32], bob_source, Some(second_seed))
        .await
        .expect("Bob's second collect settles");
    bob.sync().await;
    oracle_grant(&mut oracle, [7; 32], bob.node, 5).await;
    let third_seed = bob.reserve();
    bob.submit([8; 32], bob_source, Some(third_seed))
        .await
        .expect("Bob's third collect settles");
    alice.sync().await;

    let second_source = alice.credit(second_seed);
    let third_source = alice.credit(third_seed);
    let second_output = alice.reserve();
    ledger.lock().expect("ledger is not poisoned").reject_next = true;
    assert!(
        alice
            .submit(second, second_source, Some(second_output))
            .await
            .is_err(),
        "Alice's collect never reaches a block"
    );
    assert_eq!(alice.status(second), Some(SubmissionStatus::Pending));

    let mut competing = alice.restore().await;
    let competing_output = competing.reserve();
    assert!(
        competing
            .submit([9; 32], third_source, Some(competing_output))
            .await
            .is_err(),
        "a seed-restored wallet cannot collect onwards before the invitation is reimported"
    );
    competing
        .facade()
        .import_invitation(alice_account, carol_invitation.clone())
        .expect("the invitation is reimported for the recorded parent");
    competing
        .submit([9; 32], third_source, Some(competing_output))
        .await
        .expect("the restored wallet collects the credit of equal value");
    alice.sync().await;
    assert_eq!(
        alice.reward_balance(),
        10,
        "the competing wallet spent the participant note Alice's proof pinned, for the same amount"
    );

    assert_eq!(
        alice.reconcile(second).await,
        SubmissionStatus::Rejected,
        "a participant note another proof has spent can never carry this one"
    );

    let rejected = alice.recorded(second).transaction.hash();
    alice
        .facade()
        .import_invitation(alice_account, foreign_invitation(0x33, carol.node))
        .expect("another invitation for the same parent node is accepted locally");
    assert!(
        alice
            .submit(second, second_source, Some(second_output))
            .await
            .is_err(),
        "a replacement may not deliver this reference's credit to another account"
    );
    assert_eq!(
        alice.status(second),
        Some(SubmissionStatus::Rejected),
        "the refused replacement leaves the recorded operation as it was"
    );
    assert_eq!(alice.recorded(second).transaction.hash(), rejected);

    alice.import(carol_invitation);
    let (_hash, status) = alice
        .submit(second, second_source, Some(second_output))
        .await
        .expect("the rejected operation is rebuilt against the note the competing wallet left");
    assert_eq!(status, SubmissionStatus::Pending);
    alice.sync().await;
    assert_eq!(alice.reward_balance(), 15);
    assert_eq!(
        alice.facade().state(second_source).ok(),
        Some(State::Credit {
            recipient_node: alice.node,
            amount: 0,
        }),
        "the second credit was collected exactly once"
    );
}

#[test]
async fn a_settlement_that_cannot_be_persisted_keeps_the_intent_it_would_have_cleared() {
    let (_ledger, address, _handle) = start_sequencer().await;
    let mut carol = member(address, 3).await;
    let mut bob = member(address, 1).await;
    let account = bob.account;
    let reference = [0xE2; 32];

    carol.register(None).await;
    bob.import(carol.invitation());
    bob.authorize(Some(carol.node));
    bob.reserve();
    bob.facade()
        .submit(reference, register(account))
        .await
        .expect("the registration is broadcast");

    let (_config, storage, _statistics) = bob.home.paths();
    std::fs::remove_file(&storage).expect("the storage file exists");
    std::fs::create_dir_all(&storage).expect("a directory now blocks the storage path");

    assert!(
        bob.facade().reconcile(reference).await.is_err(),
        "a settlement that cannot be recorded fails"
    );
    assert_eq!(
        bob.status(reference),
        Some(SubmissionStatus::Pending),
        "the operation keeps the status it was last persisted with"
    );
    assert!(
        bob.facade().pending_registration(account).is_some(),
        "the registration the settlement would have cleared survives"
    );
    let rolled_back = bob
        .facade()
        .intent(account)
        .expect("the intent survives")
        .clone();
    assert_eq!(
        rolled_back.pending_credits.len(),
        1,
        "and so does the credit reservation"
    );
    assert!(
        rolled_back.invitation.is_some(),
        "and the referrer's invitation"
    );

    std::fs::remove_dir(&storage).expect("the blocking directory is removed");
    assert_eq!(
        bob.facade()
            .reconcile(reference)
            .await
            .expect("the settlement is recorded once the path is writable again"),
        SubmissionStatus::Settled,
        "the failed write was a settlement, not an inconclusive inclusion"
    );
}
