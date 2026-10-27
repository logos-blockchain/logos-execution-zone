# Payment streams and vesting

## Goal

A payer locks funds and a recipient can withdraw them at a rate over time: a salary stream, a vesting schedule with a cliff, a subscription paid per second. The recipient should be able to withdraw without the payer's involvement, the payer should (optionally) be able to cancel, and both sides should have the option of being private.

Time comes only from the clock, and the clock is public state, so every stream design is built on pattern 14 (clock proposal) with the stream's accounting either public or private.

## Design A: public stream, any recipient

### Accounts

| Account | Placement | Contents |
|---|---|---|
| Stream | any public account the payer chooses | `Stream { payer: Option<AccountId>, start_ms, end_ms, total, withdrawn, gate, vault: AccountId, vault_seed: PdaSeed }` |
| Vault | a PDA of the program under `vault_seed` | native balance (or a token holding), plus `{ stream: AccountId }` in the program's own shard, written once |
| Clock | `CLOCK_01_PROGRAM_ACCOUNT_ID` | read-only |
| Recipient | anything: public account, or a fresh private slot under the recipient's key per withdrawal | credited |

`recipient_gate` decides who may withdraw: `Account(id)` (a public account that must be authorized), `Secret(H(s))` (a private recipient proving knowledge in a private transaction, pattern 11), or `Anyone` (the stream pays whoever asks, into a fixed destination).

### Instructions and effects

```rust
enum Instruction {
    Open     { start_ms: u64, end_ms: u64, total: u128, gate: Gate, vault_seed: PdaSeed },
    Withdraw { now_ms: u64, amount: u128, secret: Option<[u8; 32]>, vault_seed: PdaSeed },
    Cancel   { now_ms: u64, refund: u128, vault_seed: PdaSeed },
}
enum Effect {
    OpenStream(Stream),                           // write_once; names the vault and its seed
    BindVault { stream: AccountId },              // write_once on the vault's own shard
    TimestampIs(u64),                             // clock guard: exact, for accounting
    TimestampAtLeast(u64),                        // clock guard: lower bound
    Withdraw { now_ms: u64, amount: u128, gate_proof: GateProof, vault: AccountId, vault_seed: PdaSeed }, // guard+update on the stream
    Cancel   { now_ms: u64, refund: u128 },       // guard+update
}
```

### A simple version

```rust
fn vested(s: &Stream, now: u64) -> u128 {
    if now <= s.start_ms { return 0; }
    if now >= s.end_ms { return s.total; }
    let elapsed = u128::from(now - s.start_ms);
    let span = u128::from(s.end_ms - s.start_ms);
    s.total * elapsed / span
}

fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match ix {
        Instruction::Open { start_ms, end_ms, total, gate, vault_seed } => {
            // accounts: stream (this program's shard), vault (this program's shard), vault (native),
            //           payer (native, authorized)
            let [stream, vault_record, vault_balance, payer] = <&[_; 4]>::try_from(input.accounts.as_slice()).unwrap();
            assert_eq!(vault_record.account_id, vault_balance.account_id);
            assert!(payer.is_authorized);
            plan.effect(stream, &Effect::OpenStream(Stream {
                payer: Some(payer.account_id), start_ms, end_ms, total, withdrawn: 0, gate,
                vault: vault_balance.account_id, vault_seed,
            }));
            plan.effect(vault_record, &Effect::BindVault { stream: stream.account_id });
            plan.call(ChainedCall::new(NATIVE_TOKEN_PROGRAM_ID,
                vec![ProgramShardSelector::from(payer), ProgramShardSelector::from(vault_balance)],
                &native_token::Instruction::Transfer { amount: total }));
        }
        Instruction::Withdraw { now_ms, amount, secret, vault_seed } => {
            // accounts: stream, clock, vault (native), recipient (native), [gate account]
            let [stream, clock, vault, recipient, rest @ ..] = input.accounts.as_slice() else { panic!() };
            assert_eq!(clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);     // public by design
            let gate_proof = match (secret, rest) {
                (Some(s), []) => GateProof::Secret(sha256(&s)),
                (None, [acct]) => { assert!(acct.is_authorized); GateProof::Account(acct.account_id) }
                _ => panic!("gate"),
            };
            // `now_ms` is a lower bound: the clock must have reached it. Vesting is monotone in
            // time, so a settlement later than proposed can only make the withdrawal more valid.
            plan.inspect(clock, clock.program_account_id, &Effect::TimestampAtLeast(now_ms));
            // The stream record, not an address computation, says which vault and seed are its own.
            plan.effect(stream, &Effect::Withdraw { now_ms, amount, gate_proof,
                                                    vault: vault.account_id, vault_seed });
            plan.call(custody_transfer(vault.account_id, vault_seed, recipient.account_id, amount));
        }
        _ => todo!(),
    }
    plan
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::OpenStream(s) => Some(write_once(pre_data, s.to_bytes())),
        Effect::BindVault { stream } => Some(write_once(pre_data, stream.to_bytes().to_vec())),
        Effect::TimestampAtLeast(t) => {
            assert!(ClockAccountData::from_bytes(pre_data).timestamp >= t, "too early"); None
        }
        Effect::Withdraw { now_ms, amount, gate_proof, vault, vault_seed } => {
            let mut s = Stream::from_bytes(pre_data);
            assert!(s.gate.admits(&gate_proof), "not the recipient");
            assert_eq!(s.vault, vault, "not this stream's vault");
            assert_eq!(s.vault_seed, vault_seed, "wrong seed");
            let available = vested(&s, now_ms).checked_sub(s.withdrawn).expect("accounting");
            assert!(amount <= available, "not vested yet");
            s.withdrawn += amount;
            Some(s.to_bytes())
        }
        _ => todo!(),
    }
}
```

Because no address is derived, the same program serves a stream whose record is a public account and a stream whose record and vault are the private PDA of Design B below; only the wallet's account list changes.

The clock guard is `>=` on purpose. In a private transaction it runs at settlement; a recipient who proves at `now_ms` and lands a block later still passes, and the stream's own accounting uses the *proposed* `now_ms`, which is at most the real time, so the recipient can never withdraw more than has actually vested. Using an exact `TimestampIs` here would make every private withdrawal race the clock and lose.

`Cancel` mirrors it with `TimestampAtLeast` and a refund guard `refund == total - vested(now) - withdrawn`; the payer signs. Note a cancel and a withdraw prepared against the same stream can both settle (the stream effects are applied in order and each re-checks the live record), so a recipient cannot be cheated by a race, only preempted.

{{#include ../diagrams/streams-public-stream-private-recipient.svg}}

> **With actors.** Releasing to a private recipient is a plain public transaction that anyone can send. The money waits in the recipient's mailbox and is collected into one account, instead of a new account per withdrawal.

### Interoperability matrix

| Payer | Recipient | Withdrawal tx | Chain sees per withdrawal |
|---|---|---|---|
| Pub | Pub | public, recipient signs | recipient, amount, time |
| Pub | Priv (secret gate) | private, no signature, destination is a fresh slot under the recipient's key | stream `Withdraw { now, amount, gate: H(s) }` and the vault debit: **amount and time, not the recipient** |
| Priv (funds a public vault at open) | any | as above | the opening deshields `total` into the vault; the payer is hidden |

Amounts and times are public in every row because the stream record is public. The recipient's identity is hidden when gated by secret.

## Design B: private stream, non-cancellable

Put the whole stream inside the recipient's private state:

| Account | Placement |
|---|---|
| Stream record | this program's shard on a **private PDA** `for_private_pda(program, H(stream_id), recipient_npk, recipient_vpk, Identifier::ZERO)` |
| Funds | the **native shard of that same private PDA** |
| Recipient's spending account | a private regular account of the recipient |

`Open` is a private transaction by the payer that **initializes** the PDA (anyone may initialize a private account) with the stream record in the program's shard and `total` in its native shard, via a transfer from the payer. From then on only the recipient can update it (`nsk`), and only the program can authorize it (seed). `Withdraw` is the recipient's private transaction: `Update` the PDA (program guard on the record, clock guard on the public clock), and `custody_transfer` from the PDA's native shard to the recipient's own account.

Chain sees, per withdrawal: one clock guard effect `TimestampAtLeast(now)` on the public clock account. The amount, the stream, the recipient: nothing. The `Open` shows a debit on the payer if the payer is public, otherwise nothing.

Cost: **the payer cannot cancel**. The record lives in a note only the recipient can update. To make it cancellable, the PDA must be under a **pairwise group key** the payer and recipient share, which makes both able to update it (the program's rules still decide what each may do) and makes the stream single-writer between them, which for two parties is fine.

{{#include ../diagrams/streams-private-stream.svg}}

## Design C: private payroll

Many recipients, one payer, all hidden: one Design-B stream per employee, each opened by a private transaction from the employer's private account. Seven private accounts per transaction means each `Open` handles at most three streams (payer note, plus PDA record and native shard are one account with two shards, so actually up to six streams per transaction if the payer's account counts once). Withdrawals are independent and unlinkable. The employer learns nothing about when employees withdraw.

## Vesting

Vesting is a stream with a cliff: `vested(now) = 0` until `cliff_ms`, then linear. Add `cliff_ms` to the record and one line to `vested`. Token vesting replaces `custody_transfer` with the token program's `Transfer` and a token holding in the vault.

## Ideas

- **Streams as salary in private tokens.** Design B with a token shard instead of native: the PDA holds a token holding, withdrawals chain `token::Transfer` with the seed delegated.
- **Cancellable and private**: pairwise group key, as above. Or a hybrid: public stream record (times and amounts public), private funds in a group-held PDA (balance hidden), which hides nothing extra and is not worth it.
- **Top-ups.** A public vault can be topped up by anyone with a plain transfer; the stream record's `total` then needs an `Extend` instruction with a vault-balance inspect. A private PDA cannot be topped up by the payer after opening (they cannot update the note), unless the recipient hands the payer a [deposit key](../foundations/private-accounts.md#deposit-keys-sharing-nsk-and-vsk-without-ask) for it: then the payer can credit the same private stream account repeatedly, sees its balance, and still cannot withdraw.
- **What does not work:** "pay per block automatically". Nothing runs without a transaction; the recipient (or a keeper they pay) must submit withdrawals. Prepared withdrawals with validity windows can be pre-signed and handed to a keeper, at the cost of the keeper seeing them.
