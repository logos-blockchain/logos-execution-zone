# Guest API cheat sheet

All from `lee_core::program` unless noted. Source: `lee/state_machine/core/src/program/mod.rs`.

## Entry

```rust
pub fn run_program<I, E, P, D>(
    plan:  impl FnOnce(&PlanInput, I) -> Plan,      // I: BorshDeserialize, the instruction
    apply: impl FnOnce(E, &P) -> Option<D>,          // E: BorshDeserialize, the effect
) -> !                                               // P: [u8] or ShardData; D: Vec<u8> or ShardData

pub fn read_program_call<T: BorshDeserialize>() -> ProgramCall<T>   // manual dispatch
pub enum ProgramCall<T> { Plan(PlanInput, T), Apply(ApplyInput) }
pub fn apply_keep(input: ApplyInput) -> !
pub fn apply_write(input: ApplyInput, data: ShardData) -> !
pub fn write_once(pre_data: &[u8], data: Vec<u8>) -> Vec<u8>        // idempotent init helper
```

## Inputs

```rust
pub struct PlanInput {
    pub self_account_id: AccountId,
    pub caller_account_id: Option<AccountId>,
    pub accounts: Vec<AccountMeta>,
    pub instruction_data: Vec<u8>,
}
pub struct AccountMeta { pub account_id: AccountId, pub is_authorized: bool, pub program_account_id: AccountId }
impl AccountMeta { fn new(id, is_authorized, program) ; fn native_balance(id, is_authorized) }

pub struct ApplyInput {
    pub self_account_id: AccountId,
    pub selector: ProgramShardSelector,
    pub pre_data: ShardData,
    pub effect_data: Vec<u8>,
}
```

## Building a plan

```rust
impl Plan {
    pub fn new(input: &PlanInput) -> Self;                          // echoes the input
    pub fn effect<E: BorshSerialize>(&mut self, account: &AccountMeta, effect: &E);          // own shard
    pub fn inspect<E: BorshSerialize>(&mut self, account: &AccountMeta, owner: AccountId, guard: &E); // other's shard
    pub fn call(&mut self, call: ChainedCall);
    pub fn event(&mut self, event: ProgramEvent);                   // public txs only
    pub fn block_window<W: Into<BlockValidityWindow>>(&mut self, w: W);       // 5.., ..9, ..
    pub fn timestamp_window<W: Into<TimestampValidityWindow>>(&mut self, w: W);
    pub fn output(&self) -> &PlanOutput;                            // for unit tests
    pub fn write(self) -> !;                                        // run_program calls this
}

pub struct ChainedCall {
    pub program_account_id: AccountId,
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub instruction_data: Vec<u8>,
    pub pda_seeds: Vec<PdaSeed>,
}
impl ChainedCall {
    pub fn new<I: BorshSerialize>(program: AccountId, selectors: Vec<ProgramShardSelector>, ix: &I) -> Self;
    pub fn with_pda_seeds(self, seeds: Vec<PdaSeed>) -> Self;
}

pub struct ProgramEvent { pub selector: [u8; 8], pub data: Vec<u8> }   // selector = sha256("prog::Event")[..8]
```

## Selectors and ids

```rust
use lee_core::account::{AccountId, ProgramShardSelector, ShardData};
ProgramShardSelector::new(account_id, program_account_id)
ProgramShardSelector::native_balance(account_id)
ProgramShardSelector::from(&account_meta)

AccountId::for_public_pda(&program, &seed)
AccountId::for_private_pda(&program, &seed, &npk, &vpk, identifier)
AccountId::for_regular_private_account(&npk, &vpk, identifier)   // identifier: lee_core::Identifier (32 bytes)
AccountId::for_shadow_program(&image_id)
AccountId::from_builtin_program_name(b"name")                  // builtins; or clock_core::clock_account_id() etc.
AccountId::from_builtin_program(image_id)                        // test seeding only
PdaSeed::new([u8; 32]); Identifier::new([u8; 32]); Identifier::ZERO
```

## Native token

```rust
use lee_core::native_token::{self, NATIVE_TOKEN_PROGRAM_ID, Instruction, custody_transfer, decode_balance, encode_balance};
Instruction::Transfer { amount: u128 }                      // accounts: [sender (authorized), recipient], native shards
custody_transfer(from, seed, to, amount) -> ChainedCall     // transfer with `seed` delegated for `from`
decode_balance(&[u8]) -> Result<u128, _>                    // empty = 0
```

## Clock

```rust
use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID, CLOCK_50_PROGRAM_ACCOUNT_ID, ClockAccountData};
ClockAccountData::from_bytes(pre_data) -> { block_id: u64, timestamp: u64 /* ms */ }
```

## Hashing in the guest

```rust
use risc0_zkvm::sha::{Impl, Sha256 as _};
let digest: [u8; 32] = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
```

## Validation errors you can trigger

| Error | Cause |
|---|---|
| `EffectOutsideInputs` | effect selector not among the call's selectors |
| `AccountShardSelectorsNotUnique` | duplicate selector in a call |
| `ForeignShardWrite` | `apply` returned `Some` for a shard you do not own |
| `PlanInputMismatch` / `ApplyInputMismatch` | hand-rolled output with a wrong echo |
| `UnknownAccount` | chained call names an account not in the root call |
| `MaxChainedCallsExceeded` | more than 10 chained calls |
| `FamilyBindingConflict` | two accounts under one `(program, seed)` in a transaction |
| `EmptyBlockWindowIntersection` / `EmptyTimestampWindowIntersection` | contradictory windows |
| `ProgramExecutionFailed("Guest panicked: …")` | your `assert!`/`panic!` |
| `OutOfGas` | over the public cycle budget |

## Host-side, for wallets and tests

```rust
use lee::{PublicTransaction, public_transaction::{Message, WitnessSet}, FeeDeclaration};
Message::try_new(program, selectors, nonces, instruction)                 // fee-exempt shape
Message::try_new_with_fees(program, selectors, nonces, instruction, FeeDeclaration::new(payer, gas_limit, tip, max_fee))
WitnessSet::for_message(&message, &[&private_key])

use lee::{ProvingInput, execute_and_prove, privacy_preserving_transaction::circuit::ProgramWithDependencies};
ProgramWithDependencies::new(program, program_account_id, HashMap<AccountId, Program>)
    .as_shadow_program() / .with_shadow_dependency(id)
    .as_undisclosed_program(header, membership_proof) / .with_undisclosed_dependency(id, header, proof)
ProgramWithDependencies::native()

use wallet::{WalletCore, AccountIdentity};
AccountIdentity::{Public(id), PublicNoSign(id), PrivateOwned(id), PrivateForeign{npk,vpk,kind}, PrivateShared{..}, PrivatePdaShared{..}}
    .balance() / .select_program_shard(program)
wallet.send_pub_tx(accounts, instruction_bytes, program).await
wallet.send_privacy_preserving_tx(accounts, instruction_bytes, &program_with_dependencies).await
```
