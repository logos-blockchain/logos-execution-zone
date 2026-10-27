# Private donations

## Goal

A charity publishes one key. Anyone can send it money, from a public or a private account, so that an observer of the chain cannot tell who donated, how much, or how much the charity has received in total. The charity can spend what it received, privately or publicly, later.

This needs **no program**. It is the native receive model used well. A second half of the chapter adds a small program for the things a plain transfer cannot do: receipts, matching, refunds.

## Accounts

| Account | Placement | Authorized by |
|---|---|---|
| Donor | public key-held, or private regular | signature, or `ask` |
| Donation slot | private regular account under the charity's key, fresh identifier per donation | initialized by the donor's transaction, then only by the charity |

The charity publishes `(npk, vpk)`:

```bash
wallet account new private-accounts-key
wallet account show-keys --account-id Private/<any account under that key> > charity.keys
```

## The transaction

Each donor lists two selectors: their own native balance, authorized, and a fresh private account of the charity's:

```rust
wallet.send_privacy_preserving_tx(
    vec![
        AccountIdentity::PrivateOwned(donor).balance(),          // or Public(donor) for a public donor
        AccountIdentity::PrivateForeign {
            npk: charity_npk, vpk: charity_vpk,
            kind: PrivateAccountKind::Regular(random_identifier),
        }.balance(),
    ],
    Program::serialize_instruction(native_token::Instruction::Transfer { amount })?,
    &ProgramWithDependencies::native(),
).await
```

On the command line this is `wallet auth-transfer send --from <donor> --to-keys charity.keys --amount N`; the wallet picks the identifier. The charity runs `wallet account sync-private` and finds one new account per donation.

{{#include ../diagrams/donations-three-placements.svg}}

> **With actors.** A public donor sends a plain signed transfer, with no proof, and the charity collects every donation into one account instead of finding a new account per donation.

## Interoperability matrix

| Donor | Slot | Works | Chain sees |
|---|---|---|---|
| Priv | Priv | yes | 7 private actions, no public actions, no signatures, no program claims. Nothing else. |
| Pub | Priv | yes | the donor's account id and signature, a `Debit(amount)` on it: **who and how much**, not to whom |
| Priv | Pub (charity's public account) | yes | `Credit(amount)` on the charity: **how much and to whom**, not from whom |
| Pub | Pub | yes | everything; an ordinary transfer |

The private→private row is the strongest privacy the protocol offers: a native transfer makes no program claim and both endpoints are notes.

## What leaks

- **Nothing about the amount or the donor**, in the private→private case. The transaction is indistinguishable from any other private native transfer of the same shape (two real notes among seven).
- **The identifier matters.** The slot's init nullifier is `H(account_id)`. If the charity published identifiers or donors used a predictable one (a counter, a hash of their name), an observer who computes the id sees the donation land. Random identifiers are what the wallet does by default; keep it that way.
- **The view tag** of every slot is the same byte (it depends only on the charity's key). Over many donations, notes with that tag are 256 times more likely to be the charity's than a random note. This narrows "is this a donation to X" from 1 in N to roughly 1 in N/256, and only for someone who knows the charity's key, which is public. It never reveals amounts or donors.
- **Timing and shape.** A private transfer whose only real notes are one `Update` and one `Init` is the shape of a payment. Many transactions have that shape.
- **Spending.** When the charity later deshields or pays a public account, the amount and the recipient are public. Sweeping many slots into one private account first (an `Update` of one and `Update` of others to zero, seven per transaction) keeps the total off chain.

## Limits to know

- The charity cannot be paid twice into the same slot; every donation is a new account. This is a feature (unlinkability) and a cost (one sync entry per donation, seven-per-transaction sweeps).
- A donor who loses the transaction has no receipt. Add the program below for that.
- Private transactions are fee-exempt today, so a donation costs the donor only proving time. When private fees arrive, a fee payer will appear in the transaction and the private→private row will need re-reading.

## A donation program

Three things a bare transfer cannot do: give the donor a **receipt**, let a sponsor **match** donations, and **refund** if a goal is missed. All three are small.

### Accounts

| Account | Placement | Notes |
|---|---|---|
| Campaign | any public account the organizer chooses (its own signed account, or a PDA) | `Campaign { charity_npk, charity_vpk, goal, raised, deadline_ms, state, match_vault: AccountId, match_seed: PdaSeed }` |
| Match vault | a PDA of the program under `match_seed`, chosen by the organizer | native balance, funded by a sponsor; its own donation-program shard records `{ campaign: AccountId }` |
| Donation slot | private regular under the charity's key | as above |
| Receipt | private PDA of the program, seed `H("receipt", campaign_id)`, under the donor's key, identifier chosen by the donor | `Receipt { amount, campaign_id }` |

### Instructions and effects

```rust
#[derive(BorshSerialize, BorshDeserialize)]
enum Instruction {
    Create { goal: u128, deadline_ms: u64, charity: ([u8; 32], Vec<u8>), match_seed: PdaSeed },
    Donate { amount: u128, match_amount: u128, now_ms: u64, match_seed: PdaSeed },
    Close  { now_ms: u64, reached: bool },
    Refund { amount: u128 },
}

#[derive(BorshSerialize, BorshDeserialize)]
enum Effect {
    CreateCampaign(Campaign),                       // write_once; records the match vault's id and seed
    BindVault { campaign: AccountId },              // write_once on the vault's own shard
    RecordDonation { amount: u128, match_amount: u128, match_vault: AccountId, match_seed: PdaSeed }, // guard: open, vault and seed match; raised += amount + match
    TimestampAtMost(u64),                           // guard on clock (before deadline)
    TimestampAtLeast(u64),                          // guard on clock (after deadline)
    MatchVaultAtLeast(u128),                        // guard on match vault native balance
    IssueReceipt { amount: u128 },                  // write receipt (donor's private PDA), once
    CloseCampaign { reached: bool },                // guard: raised >= goal iff reached
    ConsumeReceipt { amount: u128 },                // guard: campaign failed; clear receipt
}
```

### A simple version

```rust
fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match ix {
        Instruction::Create { goal, deadline_ms, charity, match_seed } => {
            // accounts: campaign (this program's shard), match vault (this program's shard)
            let [campaign, match_vault] = <&[_; 2]>::try_from(input.accounts.as_slice()).expect("two accounts");
            // Ids come from the handles. Neither side is derived: the pair is bound by two
            // write-once records that name each other.
            plan.effect(campaign, &Effect::CreateCampaign(Campaign {
                charity, goal, deadline_ms, raised: 0, state: State::Open,
                match_vault: match_vault.account_id, match_seed,
            }));
            plan.effect(match_vault, &Effect::BindVault { campaign: campaign.account_id });
        }
        Instruction::Donate { amount, match_amount, now_ms, match_seed } => {
            // accounts: campaign, clock, donor (native, authorized), slot (native),
            //           match vault (native), receipt (this program's shard)
            let [campaign, clock, donor, slot, match_vault, receipt] =
                <&[_; 6]>::try_from(input.accounts.as_slice()).expect("six accounts");
            assert_eq!(clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);   // the clock is public by design
            assert!(donor.is_authorized, "donor must authorize");
            assert!(amount > 0);

            // guards on public state, evaluated at settlement
            plan.inspect(clock, clock.program_account_id, &Effect::TimestampAtMost(now_ms));
            plan.effect(campaign, &Effect::RecordDonation {
                amount, match_amount, match_vault: match_vault.account_id, match_seed });
            if match_amount > 0 {
                plan.inspect(match_vault, NATIVE_TOKEN_PROGRAM_ID, &Effect::MatchVaultAtLeast(match_amount));
                // The runtime authorizes the vault only if it is this program's PDA under
                // `match_seed`, and the campaign guard above pinned that the vault named here is
                // the one the campaign was created with.
                plan.call(custody_transfer(match_vault.account_id, match_seed, slot.account_id, match_amount));
            }
            // the donation itself: an ordinary authorized transfer into the slot
            plan.call(ChainedCall::new(NATIVE_TOKEN_PROGRAM_ID,
                vec![ProgramShardSelector::from(donor), ProgramShardSelector::from(slot)],
                &native_token::Instruction::Transfer { amount }));
            // the donor's receipt, in the donor's private PDA (this program's shard)
            plan.effect(receipt, &Effect::IssueReceipt { amount });
        }
        // Close, Refund: same shape, see below
        _ => todo!(),
    }
    plan
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::CreateCampaign(c) => Some(write_once(pre_data, c.to_bytes())),
        Effect::BindVault { campaign } => Some(write_once(pre_data, campaign.to_bytes().to_vec())),
        Effect::TimestampAtMost(t) => {
            assert!(ClockAccountData::from_bytes(pre_data).timestamp <= t, "campaign closed"); None
        }
        Effect::MatchVaultAtLeast(n) => {
            assert!(decode_balance(pre_data).unwrap() >= n, "match vault too low"); None
        }
        Effect::RecordDonation { amount, match_amount, match_vault, match_seed } => {
            let mut c = Campaign::from_bytes(pre_data);
            assert!(c.state == State::Open);
            assert_eq!(c.match_vault, match_vault, "not this campaign's match vault");
            assert_eq!(c.match_seed, match_seed, "wrong vault seed");
            c.raised = c.raised.checked_add(amount).unwrap().checked_add(match_amount).unwrap();
            Some(c.to_bytes())
        }
        Effect::IssueReceipt { amount } => {
            assert!(pre_data.is_empty(), "one receipt per slot");
            Some(Receipt { amount }.to_bytes())
        }
        Effect::ConsumeReceipt { amount } => {
            let r = Receipt::from_bytes(pre_data);
            assert_eq!(r.amount, amount);
            Some(Vec::new())                     // clear the receipt
        }
        _ => todo!(),
    }
}
```

Nothing in this program computes an account id. The campaign may therefore be a public account of any kind, and the match vault may be a public PDA or, for a sponsor who wants to hide the match budget, a private PDA under the sponsor's key initialized with the funds: `custody_transfer` works on either because authorization comes from the seed grant, not from the address ([pattern 17](../patterns/index.md)). The clock is the one address the plan asserts, and it is public by design.

`Refund` is the mirror: the donor lists the campaign (guard `state == Failed`), their receipt (`ConsumeReceipt`), and a destination; the program chains a `custody_transfer` out of the campaign's own vault. For refunds to be possible the donations must have gone into a **program vault** (a public PDA), not straight into the charity's private slots, because the program cannot later pull money back out of a private account it does not hold keys for. So a refundable campaign is public in its total and per-donation amounts (the `RecordDonation` bytes), while donors stay hidden if they donate privately.

{{#include ../diagrams/donations-campaign.svg}}

### Interoperability matrix for the program

| Donor | Where donations sit | Receipt | Refundable | Chain sees per donation |
|---|---|---|---|---|
| Priv | charity's private slots | donor's private PDA | no | `RecordDonation{amount}` on the campaign (amount, not donor); if matched, the match vault debit |
| Priv | program vault (public PDA) | donor's private PDA | yes | amount (vault credit and campaign record); donor hidden |
| Pub | either | private PDA under the donor's key, if the donor has one | either | donor id and amount |
| any | private slots, no campaign record | private | no | nothing (that is the bare transfer) |

The campaign record is the price of matching and refunds: a public running total means every donation's amount is public. A campaign that wants hidden amounts drops `RecordDonation` and with it the goal logic, and matches a **fixed unit** per donation instead of a proportion, so the match transfer reveals only that a donation happened.

## Variations and ideas

- **Receipts as proofs.** A donor can later prove "I donated at least X to campaign C" by a private transaction that inspects their receipt PDA (in the proof) and emits a public effect `Attest { campaign, at_least: X }` on some verifier's public shard. The receipt never leaves the proof. See [Tickets, attestations and registries](access-and-attestations.md).
- **Anonymous top-donor board.** Not possible without revealing amounts: a board is public state and every entry is a public effect. A private ranking would need the charity to compute it off chain from its notes, which it can.
- **Recurring donations.** A payment stream from the donor's public vault to the charity's private slots, one fresh slot per withdrawal; see [Payment streams](streams.md).
- **Sweeping.** A "consolidate" transaction is seven private accounts at a time: one destination `Update` and six sources set to zero. A charity with thousands of small slots does many sweeps; each is a private transaction with no public footprint.
- **Charity spending privately.** Paying suppliers into *their* published keys keeps the whole flow off the public ledger. The only public moment is a deshield.
- **A deposit key for a trusted collector.** If the charity gives one party (its own back office, a payment processor) a [deposit key](../foundations/private-accounts.md#deposit-keys-sharing-nsk-and-vsk-without-ask) for a single private account, that party can top up the *same* account repeatedly instead of the charity sweeping one slot per donation. Donors still pay into fresh slots; the collector sweeps them into the deposit-key account. The collector can see the balance and cannot spend it.
- **What does not work:** "donate to the charity's *existing* private account" (only the charity can update it), and "goal-based refunds with hidden amounts" (the total must be public to be checked at settlement by strangers' transactions).
