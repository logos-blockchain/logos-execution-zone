# Built-in programs

LEZ v0.3 supports the following built-in programs, loaded at genesis. They are immutable, and each is addressed by name at `from_builtin_program_name(name)` (see [`lee-specs.md`](../lee-specs.md)), so a program's address does not change when its code does.

Every zone registers:

- Clock (`clock`)
- Fee (`fee`)
- Bridge (`bridge`)
- Sequencer Stake (`sequencer_stake`)

Zones configured with `cross_zone` also register:

- Cross-zone Inbox (`cross_zone_inbox`)
- Cross-zone Outbox (`cross_zone_outbox`)
- Bridge Lock (`bridge_lock`)
- Wrapped Token (`wrapped_token`)
- Ping Sender (`ping_sender`) and Ping Receiver (`ping_receiver`)

Native balance transfers and program deployment are not LEZ programs: they are LEE's native built-ins, the native token program and the program loader (see [`lee-specs.md`](../lee-specs.md)).


## Clock program

Records the current block ID and timestamp into three dedicated clock accounts, updated at different cadences (every 1, 10, and 50 blocks). Programs that need recent timestamps can read whichever granularity matches their needs.

```rust
const CLOCK_01_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(*b"/LEZ/ClockProgramAccount/0000001");
const CLOCK_10_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(*b"/LEZ/ClockProgramAccount/0000010");
const CLOCK_50_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(*b"/LEZ/ClockProgramAccount/0000050");

struct ClockAccountData {
    block_id: u64,
    timestamp: Timestamp,
}

struct Instruction {
    timestamp: Timestamp,
    block_id: u64,
}
```

The clock accounts are created at genesis with their data in the clock program's shard. The Clock Program is invoked **exclusively by the sequencer as the last transaction in every block**: users cannot invoke it directly. Its single instruction carries the new block's `timestamp` and `block_id`, taken from the block header.

Accounts: `[CLOCK_01, CLOCK_10, CLOCK_50]`, in that order. The program always writes the `01` account, and its apply checks that the new `block_id` is exactly one more than the one stored there. It writes the `10` and `50` accounts only when `block_id` is a multiple of the corresponding cadence.

## Fee program

Runs LEZ's fee market (see [`lez-specs.md`](../lez-specs.md), Fees). It owns three system accounts, all public PDAs of the Fee program: the **fee state** (base fees, payout window, carry, height), the **escrow** (whose balance is the payout escrow), and the **inbox** (the per-block collection point, empty outside the fee invocation). The Fee program is sequencer-only: user transactions invoking it are rejected, and it refuses to be called by another program.

```rust
const FEE_STATE_SEED:  [u8; 32] = *b"/LEZ/v0.3/FeeSeed/State/0000000/";
const FEE_ESCROW_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/Escrow/000000/";
const FEE_INBOX_SEED:  [u8; 32] = *b"/LEZ/v0.3/FeeSeed/Inbox/0000000/";

fn compute_fee_state_account_id(fee_account_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&fee_account_id, &PdaSeed::new(FEE_STATE_SEED))
}
// Escrow and inbox are derived the same way from their seeds.

struct BlockFeeSummary {
    gas_used_exec: Gas,
    gas_used_stor: Gas,
    revenue_base: Balance,
    revenue_tip: Balance,
}
```

**Instructions:**

- `Distribute { summary: BlockFeeSummary, payout: Balance }` — accounts: `[fee_state, escrow, inbox, producer]`; `fee_state` is selected under the Fee program's shard, the others by native balance. The forced second-to-last transaction of every block. First checks that the inbox holds exactly the summary's base revenue plus tips. Then applies the summary to the market state (updating both base fees), drains the inbox (base revenue to escrow, tips to the producer), and pays the producer's smoothed `payout` from escrow; the transfers are chained native token transfers. `payout` must equal what the fee state's own update returns.
- `Refund { amount: Balance }` — accounts: `[inbox, payer]`, both by native balance. Returns the unspent part of a transaction's fee reserve from the inbox to its payer. Issued by the fee settlement, never by a user.

## Bridge program

Moves native tokens from Bedrock (L1) into LEZ. The **bridge account** is a public PDA of the Bridge program that holds the whole unissued supply (`u128::MAX` at genesis). Genesis allocations and L1 deposits are both `Deposit`s that draw on it. The Bridge program refuses to be called by another program.

```rust
const BRIDGE_SEED_DOMAIN_SEPARATOR: [u8; 32] = *b"/LEZ/v0.3/BridgeSeed/0000000000/";
const DEPOSIT_RECEIPT_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeDepositReceipt/0";

fn compute_bridge_account_id(bridge_program_account_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&bridge_program_account_id, &PdaSeed::new(BRIDGE_SEED_DOMAIN_SEPARATOR))
}

fn deposit_receipt_account_id(bridge_program_account_id: AccountId, l1_deposit_op_id: [u8; 32]) -> AccountId {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&DEPOSIT_RECEIPT_SEED_DOMAIN);
    bytes[32..].copy_from_slice(&l1_deposit_op_id);
    AccountId::for_public_pda(&bridge_program_account_id, &PdaSeed::new(sha256(bytes)))
}
```

**Instructions:**

- `Deposit { l1_deposit_op_id: [u8; 32], recipient_id: AccountId, amount: u64 }` — accounts: `[bridge_account, recipient, deposit_receipt_pda]`; the first two by native balance, the receipt under the Bridge program's shard. Transfers `amount` from the bridge account to the recipient, exactly once per `l1_deposit_op_id`: a nonempty receipt shard marks the deposit as processed and a repeat is refused. Injected by the sequencer when Bedrock finalizes a deposit, and at genesis with synthetic op ids. The transfer is a chained native token transfer, and the program emits a `Deposit` event.
- `Withdraw { amount: u64, bedrock_account_pk: [u8; 32] }` — **currently disabled**: the instruction is defined, but the program refuses it.

## Sequencer Stake program

Tracks the stakes behind the channel's sequencer committee and the channel's posting parameters. A sequencer's **ownership account** (an ordinary account it controls) backs one Bedrock sequencer key; the staked balance sits in a **stake funds** PDA derived from the ownership account. The **config** PDA holds the channel parameters and every key's standing.

```rust
const SEQUENCER_STAKE_CONFIG_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/MinSequencerStake/0000";
const SLASH_SINK_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/SlashedStakeSink/00000";

fn sequencer_stake_config_account_id(program_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&program_id, &PdaSeed::new(SEQUENCER_STAKE_CONFIG_SEED_DOMAIN))
}

fn stake_funds_account_id(program_id: AccountId, ownership_id: &AccountId) -> AccountId {
    AccountId::for_public_pda(&program_id, &PdaSeed::new(ownership_id.to_bytes()))
}

fn slash_sink_account_id(program_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&program_id, &PdaSeed::new(SLASH_SINK_SEED_DOMAIN))
}

/// A valid Ed25519 public key: the Bedrock sequencer identity a stake backs.
struct SequencerKey([u8; 32]);

struct SlashApproval {
    signer: SequencerKey,
    signature: List<u8>,   // Ed25519 signature bytes
}

struct ChannelParams {
    minimum_sequencer_stake: u128,
    posting_timeframe: u32,   // slots per turn
    posting_timeout: u32,     // idle slots before a turn passes on
    exit_delay: u64,          // blocks before an unstake may be released
}

struct SequencerStakeConfig {
    channel_params: Option<ChannelParams>,
    channel_id: Option<[u8; 32]>,
    entries: BTreeMap<SequencerKey, SequencerEntry>,
}

struct SequencerEntry {
    account_id: AccountId,          // the ownership account
    total_staked: u128,
    total_pending_unstake: u128,
}
```

A key is an accredited committee member while `total_staked - total_pending_unstake ≥ minimum_sequencer_stake`.

**Instructions:**

- `InitChannelParams { params: ChannelParams, channel_id: [u8; 32] }` — accounts: `[config]`. Sets the channel parameters and channel id once, at genesis; rejected once they are set.
- `Stake { sequencer_key: SequencerKey, amount: u128, has_record: bool }` — accounts: `[funding_account, ownership_account, stake_funds, config]`. Top-level only; the ownership account must be authorized, and so must the funding account, since the funds move through a chained native token transfer. Locks `amount` from the funding account into the ownership account's stake funds PDA and records it against `sequencer_key`. First use initializes the ownership account's shard for this program.
- `UnstakeRequest { sequencer_key: SequencerKey, amount: u128, destination: AccountId, requested_at: u64 }` — accounts: `[ownership_account, config]`. Top-level only; the ownership account must be authorized. Records a request to release `amount` to `destination`; no balance moves yet. Must leave the key either fully exited or still at or above the minimum.
- `FinalizeUnstake { sequencer_key: SequencerKey, amount: u128, requested_at: u64, exit_delay: u64 }` — accounts: `[ownership_account, stake_funds, destination, config]`. Unsigned and permissionless: releases a pending request once `exit_delay` blocks have passed since it. The sequencer submits these automatically.
- `Slash { sequencer_key: SequencerKey, inscription: [u8; 32], approvals: List<SlashApproval>, total_staked: u128 }` — accounts: `[ownership_account, stake_funds, slash_sink, config]`. Burns the key's whole stake into the sink PDA and removes its entry. Authorized only by `approvals`: Ed25519 signatures from two thirds of the committee (never fewer than two) over a message binding the channel id, the offending `sequencer_key`, and the inscription (see [`lez-specs.md`](../lez-specs.md), Slash approvals). The offence itself is not checked.

## Cross-zone Inbox program

Delivers finalized messages from peer zones to their target programs. Sequencer-only: the destination sequencer injects a `Dispatch` for each message addressed to its zone, user transactions invoking the inbox are rejected, and the inbox refuses to be called by another program.

```rust
/// A zone's id: its Bedrock channel id.
type ZoneId = [u8; 32];

struct CrossZoneMessage {
    src_zone: ZoneId,
    src_block_id: u64,
    src_block_hash: [u8; 32],       // recomputed from the source block's contents
    src_tx_index: u32,
    src_account_id: AccountId,      // the emitting program on the peer zone
    target_account_id: AccountId,   // the program on this zone
    payload: List<u8>,
    l1_inclusion_witness: Option<List<u8>>, // reserved; must be None
}
```

Replays are refused through a **seen shard**, a PDA of the inbox per `(src_zone, src_block_id)`. The first delivery from a peer block binds the shard to that block's `src_block_hash`, so a second, different block at the same ID (an equivocating peer) is refused. The shard then records each delivered `src_tx_index`, and a repeat is refused.

**Instructions:**

- `Dispatch(CrossZoneMessage)` — accounts: `[config, seen_shard_pda, source_marker_pda, …target accounts]`. Refuses a message whose `src_zone` is this zone, records the delivery in the seen shard, and chain-calls `target_account_id` with the message's payload as instruction data. The target receives the **source marker** account (a PDA of the inbox per `(src_zone, src_account_id)`, naming who sent the message) at position 0, selecting its native balance, followed by the remaining accounts; no PDA seeds are passed. The inbox authenticates transport only: a target reachable across zones must check the marker against the sources it authorized itself, as Wrapped Token and Ping Receiver do.
- `InitConfig(InboxConfig)` — accounts: `[config]`. Initializes the inbox config PDA at genesis with this zone's own id, which `Dispatch` uses to refuse messages from this zone itself.

## Cross-zone Outbox program

Records outbound cross-zone messages on the source zone. Each message is written into its own slot PDA, keyed by `(emitter, target_zone, ordinal)`, where destination watchers find it.

**Instructions:**

- `Emit { target_zone: ZoneId, target_account_id: AccountId, target_accounts: List<ProgramShardSelector>, payload: List<u8>, ordinal: u32 }` — accounts: `[outbox_slot_pda]`. Callable only through a chained call, since the caller is recorded as the emitter. Writes the message to the slot, which can be written only once. The stored emitter is the immediate chained caller (Bridge Lock or Ping Sender), while cross-zone discovery names the top-level program; the two agree only because every emitter refuses to be called by another program.

## Bridge Lock program

Moves native tokens to another zone: it locks the holder's balance on this zone and emits a message that mints the equivalent Wrapped Token on the target zone. Locked balance accumulates in an **escrow** PDA; each holder's lockable balance sits in a **holding** PDA.

**Instructions:**

- `Lock { amount: u128, target_zone: [u8; 32], target_account_id: AccountId, target_accounts: List<ProgramShardSelector>, payload: List<u8>, ordinal: u32 }` — accounts: `[config, holder, holder_holding_pda, escrow, outbox_slot_pda]`. Top-level only; the holder must be authorized, `amount` must be positive, and `payload` must decode as a Wrapped Token `Mint`. Moves `amount` from the holding PDA into escrow and emits the mint message through the outbox. Fee-exempt, since the funds come from the holding PDA rather than a spendable account.
- `InitConfig { outbox_account_id: AccountId, target_account_id: AccountId }` — accounts: `[config]`. Sets the outbox program and mint target at genesis. Repeating the same configuration is a no-op; a different one is rejected.

## Wrapped Token program

Mints the destination-side representation of balances locked by Bridge Lock on a peer zone. Its config pins the minter (the inbox) and the peer sources it may mint for, each with an optional lifetime mint cap.

**Instructions:**

- `Mint { recipient: [u8; 32], amount: u128 }` — accounts: `[source_marker, config, recipient_holding_pda]`. Delivered only by the inbox, and only for a peer source this token authorizes and within that source's cap. Credits `amount` to the recipient's holding.
- `InitConfig(WrappedTokenConfig)` — accounts: `[config]`. Written once into an empty config shard at genesis; an identical re-run is a no-op, a different one is refused.
- `UpdateSources { sources: List<SourcePolicy> }` — accounts: `[config, authority]`. Replaces the authorized sources. Refused unless the config names an authority, that account authorized the transaction, and the call is top-level or comes from the configured governance program. A source that stays listed keeps its mint counter.
- `RenounceAuthority` — accounts: `[config, authority]`. Same checks as `UpdateSources`. Gives up the authority for good, leaving the source list fixed. There is no way to reassign it.

## Ping Sender and Ping Receiver programs

A minimal cross-zone example pair.

**Ping Sender instructions:**

- `Send { target_zone: [u8; 32], target_account_id, target_accounts: List<ProgramShardSelector>, payload: List<u8>, ordinal: u32 }` — accounts: `[sender_config, outbox_slot_pda]`. Emits a cross-zone message through the pinned outbox. An empty-witness `Send` is a system-injection shape and fee-exempt.
- `InitConfig { outbox_account_id: AccountId }` — pins the outbox program, written once into an empty config shard at genesis.

**Ping Receiver instructions:**

- `Record { payload: List<u8> }` — accounts: `[source_marker, receiver_config, record_pda]`. Records the payload, delivered by the inbox on behalf of a peer source this receiver authorizes.
- `InitConfig(ReceiverConfig)`, `UpdateSources { sources: List<(ZoneId, AccountId)> }`, `RenounceAuthority` — the same configuration pattern as Wrapped Token.
