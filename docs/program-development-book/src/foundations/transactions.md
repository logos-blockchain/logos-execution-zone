# Transactions, public and private

A transaction is one root call: a program, a list of shard selectors, instruction bytes, and the authorization for some of the accounts. There are two wire forms. They differ in who executes the program and in what the chain learns.

Source: `lee/state_machine/src/public_transaction/`, `lee/state_machine/src/privacy_preserving_transaction/`, `lee/state_machine/src/validated_state_diff/mod.rs`.

## Public transactions

```rust
pub struct Message {
    pub program_account_id: AccountId,
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub nonces: Vec<Nonce>,                 // one per signature, in signature order
    pub instruction_data: InstructionData,
    pub fee: Option<FeeDeclaration>,        // None only for system-shaped transactions
}
pub struct WitnessSet { signatures_and_public_keys: Vec<(Signature, PublicKey)> }
pub struct PublicTransaction { message, witness_set }
```

Building one by hand (from `examples/program_deployment/src/bin/run_hello_world_with_authorization.rs`):

```rust
let nonces = wallet.get_accounts_nonces(&[account_id]).await?;
let message = Message::try_new_with_fees(
    program_account_id,
    vec![ProgramShardSelector::new(account_id, program_account_id)],
    nonces,
    greeting,                       // any BorshSerialize instruction
    FeeDeclaration::new(payer, gas_limit, tip, max_fee),  // a charged tx must declare one
)?;
let witness_set = WitnessSet::for_message(&message, &[&signing_key]);
let tx = PublicTransaction::new(message, witness_set);
```

The sequencer, for each public transaction in a block:

1. checks the signatures and the nonces (a failure here is malformed and rejects the block, it is never charged);
2. reserves the fee from the payer;
3. runs the root call and its chain on live state with the signers as the authorized set, under the declared gas limit;
4. on success applies the diff, on a chargeable failure applies only the nonce advances (the fee stays paid, the action reverts);
5. refunds the unspent reserve.

"Chargeable" covers everything that surfaces during or after execution: a guest panic, out of gas, an unknown program named by a chained call, a validity window miss. Only structural defects (bad signature, wrong nonce, duplicate selectors, unknown top-level program) are non-chargeable, and those reject the whole block, which a correct proposer never includes. See `LeeError::is_chargeable`.

### Fees

```rust
pub struct FeeDeclaration { payer: AccountId, gas_limit: Gas, tip: Fee, max_fee: Balance }
```

The payer must be one of the signers; its ordinary signature authorizes the fee. The reserve is `gas_limit · base_fee_exec + tx_bytes · base_fee_stor + tip` at the block's opening prices; the actual base fee is `cycles_used · base_fee_exec + tx_bytes · base_fee_stor`, with cycles clamped to `gas_limit`. `max_fee` must cover the reserve or the transaction is refused at admission. Gas is RISC Zero user cycles, one to one. The per-transaction cap is `MAX_GAS_EXEC` = 10,000,000 cycles; the block targets 5,000,000. The wallet's `send_pub_tx` picks a payer (the first funded signer) and fills the declaration; the sequencer's `fee_quote` (`lez/sequencer/core/src/fees.rs`) prices the next block so a client can size `max_fee`.

Programs never see fees. There is no "who pays" in the guest; the payer is a transaction-level choice. A program that wants to charge users has to do so explicitly with a transfer into one of its PDAs.

### Exempt shapes

Some public transactions carry `fee: None`: bridge deposits and cross-zone dispatches injected by the sequencer, cross-zone locks, and sequencer-stake operations. A user transaction that omits the fee and is none of those is rejected (`MissingFeeDeclaration`). Fee-exempt calls run under a fixed `DEFAULT_PUBLIC_CYCLE_BUDGET` of 32M cycles.

## Private transactions

A private transaction is produced by running the whole call graph on the user's machine, proving it, and publishing only what the chain needs to apply it.

```rust
pub struct Message {
    pub public_actions: Vec<PublicActionWithID>,   // per public account: deferred effects
    pub nonces: Vec<Nonce>,                        // for the public signers
    pub private_actions: Vec<PrivateAction>,       // nullifier, root, commitment, note
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub program_image_claims: Vec<ProgramImageClaim>,
}
pub struct WitnessSet { signatures_and_public_keys: Vec<(Signature, PublicKey)>, proof: Proof }
```

### Proving

The prover input (`ProvingInput`) is the root call plus one `PrivateWitness` per private account:

```rust
pub struct ProvingInput {
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub signers: HashSet<AccountId>,        // public accounts that will sign
    pub private_witnesses: Vec<PrivateWitness>,
    pub instruction_data: InstructionData,
    pub dummy_inputs: Vec<DummyInput>,      // padding
    pub ciphertext_padding: Option<u32>,    // note pad, ≤ 8 KiB
}
```

and a `ProgramWithDependencies`: every program the execution may dispatch, keyed by its deployed account id, each marked disclosed, undisclosed or shadow ([Program identity](program-identity.md)).

`execute_and_prove` runs the same `ExecutionState` the sequencer uses, with a backend that proves each guest invocation separately (one receipt for the plan, one per private-account apply) and defers every effect on a public account. It then proves the **privacy-preserving circuit**, a guest that replays the traversal, verifies every receipt against its image id, recomputes the native token calls from protocol code, and emits the message above. The wallet does all this in `send_privacy_preserving_tx`; the typical proof takes from tens of seconds to a few minutes.

Inside the circuit a public account's shard is unreadable: `Backend::public_shard` returns `PublicShardUnavailable`. Any effect that targets a public shard, whether a write by its owner or a guard by anyone, is recorded and evaluated later.

### Settlement

The sequencer, for each private transaction:

1. checks the message is well formed (non-empty private actions, unique public accounts, nullifiers, commitments), that the nonce count matches the signatures, that the signatures verify, that the nonces match the chain, and that the block and timestamp are inside the windows;
2. rebuilds the circuit output it expects: the `is_authorized` bit of every public action from the actual signers, and every `Disclosed` image claim from the program actually deployed at that account id; then verifies the proof against those bytes. A prover that lied about either produces a proof that does not verify;
3. checks the commitments are new and the nullifiers unspent against known roots;
4. **applies the deferred public effects** in the clear: for each public account, in the order the traversal emitted them, it loads the owning program from chain state, runs its `apply` against the live shard, and validates the output as usual. A panic here refuses the transaction (it is simply not included) without touching anything;
5. inserts the commitments and nullifiers, advances the public signers' nonces.

Nothing in step 4 depends on what the prover saw. That is what makes a private transaction **prepared in advance** still settle later against whatever the public shards hold, as long as every guard still passes. It is also why every public guard must be strong enough on its own: the sequencer will not re-run `plan`, only the applies.

### Fees, today

Private transactions are **fee-exempt** under the interim policy (`lez/chain_state/src/classify.rs`) and excluded from gas metering. The `FeeTxView::Private { payer }` shape and the private verification gas constant exist for a future private-payer design. Until then a refused private transaction costs its sender nothing on chain and can be resubmitted; the proof is the only cost.

## Choosing the form

| | Public | Private |
|---|---|---|
| Who executes | sequencer | user, then sequencer applies public effects |
| Accounts | public only | any mix; private ones need witnesses |
| Program dependencies | resolved on chain, may be deployed in the same tx | supplied to the prover, must already be deployed unless shadow |
| Reads of public state | live, in `apply` | only through guards evaluated at settlement |
| Failure | charged revert, nonce advances | not included, nothing changes, free to retry |
| Fees | declared and charged | exempt (interim) |
| Events | recorded | dropped |
| Latency | one block | proving time plus one block |
| Can be prepared ahead | no (nonce and gas price bound it loosely) | yes; validity windows bound it |

A program does not choose. The same `plan` and `apply` serve both forms; the wallet decides per transaction by how it lists the accounts. The examples in `examples/program_deployment/src/bin/` show one program driven both ways, and `run_hello_world_with_move_function.rs` mixes a public and a private account in one call.
