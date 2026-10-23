# Multisig, in every public/private combination

## Goal

A vault controlled by `n` members, spendable when `k` of them approve a proposal. Members may be public accounts or private ones; the vault may be public or private; the proposal board may be public or private. **One deployed program covers every combination**; what changes is how the wallet places the accounts and what each placement leaks. Going through them is the best tour of what "uniform interop" means, and of the one rule that makes it possible: the program identifies its own accounts by seed and by content, never by computing an address.

## The three placements

A multisig has three pieces of state and each can be public or private:

| Piece | Public | Private |
|---|---|---|
| **Vault** (the funds) | public PDA, seed `H(multisig_id)`; balance visible | private PDA under a **group key** shared by members; balance hidden; single writer |
| **Board** (config + proposals + approvals) | public PDAs; approvals commute, members act concurrently | one group-held private account; approvals serialize |
| **Member credential** | public account id, authorized by signature | a secret whose hash is registered; proven from instruction data in a private transaction |

## Four executions, drawn

The same deployed program, four ways of placing its accounts. Each diagram follows one proposal from creation to payout. The upper lane is what stays with the participants; the lower lane is everything the chain records. The rest of this chapter explains the code that makes each of them work.

{{#include ../diagrams/multisig-all-public.svg}}

Everything is public. Anyone can reconstruct who proposed, who approved and where the money went.

{{#include ../diagrams/multisig-anonymous-member.svg}}

Carol approves without signing anything. The chain learns that slot 2 approved, which is a pseudonym it already knew from the config, and nothing about Carol.

{{#include ../diagrams/multisig-hidden-treasury.svg}}

The board still coordinates in public, but it holds only a commitment to the action. The balance, the amount and the recipient appear nowhere; the execution is seven unlinkable private actions plus the board updates.

{{#include ../diagrams/multisig-all-private.svg}}

Nothing about the multisig is public, provided it is deployed with an immutable header and run as an [undisclosed program](../foundations/program-identity.md): otherwise every one of these transactions names the multisig in its program claims. The two execute columns are alternatives. Paying a private Dave leaves nothing but notes; paying a public Dave shows the credit and its amount, but not which vault or which multisig paid it, because the only public effect is the native token's credit on Dave. The price of all this is turn-taking: each member updates the same private board, so they act one after another.

## One program, any placement

The program below is written so that it **never computes an account id**. It identifies its own accounts in two ways only:

- **by seed**, through the runtime: when it chains `custody_transfer(vault, vault_seed, ..)`, the native token program accepts the debit only if `vault` is the multisig's PDA under `vault_seed`, public (`for_public_pda`) or private (a witness bound to `(multisig, seed)`). The multisig does not know which, and does not need to;
- **by content**, written once at init: the config records the vault's account id, and the vault's own multisig shard records the config's account id and its seed. Both ids come from the `AccountMeta`s the plan is handed, so the plan needs no derivation. Every later action pins the pair with guards on both shards.

With that, the same deployed program serves a public board over a public vault, a group-held private board over a private vault, and any mix. What changes between placements is only how the wallet lists the accounts.

### Accounts

| Account | Placement | Contents (multisig program's shard) |
|---|---|---|
| Config | any account the founders choose: a public account they hold, a public PDA, or a private account under a group key | `Config { threshold, members: Vec<Credential>, vault: AccountId }` |
| Vault | a PDA of the multisig program under `vault_seed`, public or private (group key) | native balance shard, plus `VaultRecord { config: AccountId, seed: PdaSeed }` in the multisig's shard |
| Proposal | any account, one per proposal | `Proposal { config: AccountId, action, approvals: Vec<u32>, executed }` |
| Member (public credential) | the member's public account, authorized by signature | |
| Recipient | anything the action names | |

```rust
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq)]
enum Credential {
    Account(AccountId),      // public member: must be an authorized input
    Secret([u8; 32]),        // private member: H(secret); the secret is proven in a private tx
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq)]
enum Action {
    PayNative { to: AccountId, amount: u128 },
}
```

### Instructions and effects

```rust
enum Instruction {
    Init    { threshold: u32, members: Vec<Credential>, vault_seed: PdaSeed },
    Propose { action: Action },
    Approve { member: u32, secret: Option<[u8; 32]> },
    Execute { action: Action, approvals: Vec<u32>, vault_seed: PdaSeed },
}

enum Effect {
    InitConfig(Config),                                   // write_once
    InitVault(VaultRecord),                               // write_once
    MemberIs { index: u32, credential: Credential },      // guard on config
    CreateProposal(Proposal),                             // write_once
    ProposalBelongsTo(AccountId),                         // guard on proposal: proposal.config == id
    Approve { member: u32 },                              // append if absent, refuse if executed
    ThresholdIsAndVaultIs { count: u32, vault: AccountId },   // guard on config
    VaultBoundTo { config: AccountId, seed: PdaSeed },    // guard on the vault's multisig shard
    MarkExecuted { action: Action, approvals: Vec<u32> }, // guard: same action, approvals recorded, unexecuted
}
```

### A simple version

```rust
fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match ix {
        Instruction::Init { threshold, members, vault_seed } => {
            // accounts: config (this program's shard), vault (this program's shard)
            let [config, vault] = <&[_; 2]>::try_from(input.accounts.as_slice()).unwrap();
            assert!(threshold > 0 && (threshold as usize) <= members.len());
            // The two ids are taken from the handles, never derived. Write-once on both sides
            // makes the pair unforgeable: nobody can later bind another config to this vault
            // or another vault to this config.
            plan.effect(config, &Effect::InitConfig(Config { threshold, members, vault: vault.account_id }));
            plan.effect(vault,  &Effect::InitVault(VaultRecord { config: config.account_id, seed: vault_seed }));
        }
        Instruction::Approve { member, secret } => {
            // accounts: config, proposal, [member account if public credential]
            let (config, proposal, rest) = split(&input.accounts);
            let credential = match (secret, rest) {
                (Some(s), []) => Credential::Secret(sha256(&s)),          // private member
                (None, [account]) => {
                    assert!(account.is_authorized, "member must sign");   // public member
                    Credential::Account(account.account_id)
                }
                _ => panic!("either a secret or one signed member account"),
            };
            plan.effect(config,   &Effect::MemberIs { index: member, credential });
            plan.effect(proposal, &Effect::ProposalBelongsTo(config.account_id));
            plan.effect(proposal, &Effect::Approve { member });
        }
        Instruction::Execute { action, approvals, vault_seed } => {
            // accounts: config, proposal, vault (multisig shard), vault (native shard), recipient (native)
            let [config, proposal, vault_record, vault_balance, to] =
                <&[_; 5]>::try_from(input.accounts.as_slice()).unwrap();
            assert_eq!(vault_record.account_id, vault_balance.account_id, "two shards of one vault");
            plan.effect(config, &Effect::ThresholdIsAndVaultIs {
                count: approvals.len() as u32, vault: vault_record.account_id });
            plan.effect(vault_record, &Effect::VaultBoundTo { config: config.account_id, seed: vault_seed });
            plan.effect(proposal, &Effect::ProposalBelongsTo(config.account_id));
            plan.effect(proposal, &Effect::MarkExecuted { action: action.clone(), approvals });
            match action {
                Action::PayNative { to: dest, amount } => {
                    assert_eq!(to.account_id, dest);
                    // The runtime authorizes the vault for this call only if it really is this
                    // program's PDA under `vault_seed`, whether public or private.
                    plan.call(custody_transfer(vault_balance.account_id, vault_seed, dest, amount));
                }
            }
        }
        Instruction::Propose { action } => {
            let [config, proposal] = <&[_; 2]>::try_from(input.accounts.as_slice()).unwrap();
            plan.effect(proposal, &Effect::CreateProposal(Proposal {
                config: config.account_id, action, approvals: vec![], executed: false }));
        }
    }
    plan
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::InitConfig(c)   => Some(write_once(pre_data, c.to_bytes())),
        Effect::InitVault(v)    => Some(write_once(pre_data, v.to_bytes())),
        Effect::CreateProposal(p) => { assert!(pre_data.is_empty()); Some(p.to_bytes()) }
        Effect::MemberIs { index, credential } => {
            let cfg = Config::from_bytes(pre_data);
            assert_eq!(cfg.members.get(index as usize), Some(&credential), "not a member");
            None
        }
        Effect::ProposalBelongsTo(config) => {
            assert_eq!(Proposal::from_bytes(pre_data).config, config, "proposal is for another multisig");
            None
        }
        Effect::Approve { member } => {
            let mut p = Proposal::from_bytes(pre_data);
            assert!(!p.executed);
            if !p.approvals.contains(&member) { p.approvals.push(member); }
            Some(p.to_bytes())
        }
        Effect::ThresholdIsAndVaultIs { count, vault } => {
            let cfg = Config::from_bytes(pre_data);
            assert!(count >= cfg.threshold, "below threshold");
            assert_eq!(cfg.vault, vault, "not this multisig's vault");
            None
        }
        Effect::VaultBoundTo { config, seed } => {
            let v = VaultRecord::from_bytes(pre_data);
            assert_eq!(v.config, config, "vault belongs to another config");
            assert_eq!(v.seed, seed, "wrong seed");
            None
        }
        Effect::MarkExecuted { action, approvals } => {
            let mut p = Proposal::from_bytes(pre_data);
            assert!(!p.executed && p.action == action);
            assert!(approvals.iter().all(|a| p.approvals.contains(a)), "approval not recorded");
            p.executed = true;
            Some(p.to_bytes())
        }
    }
}
```

### Why this is safe without any address in the code

- **A forged config.** An attacker can `Init` their own config anywhere, naming the real vault. But the real vault's record already names the real config (write-once), so `VaultBoundTo` fails for the forgery. And they cannot re-init the real vault's record.
- **A forged vault.** An attacker can create a PDA of the multisig under some seed in their own private family and bind a config to it. That only ever drains their own vault: `ThresholdIsAndVaultIs` on the real config names the real vault.
- **A proposal from another multisig.** `ProposalBelongsTo` pins every proposal to its config.
- **A vault that is not this program's PDA.** The chained native transfer refuses an unauthorized sender, and the only way the vault becomes authorized is the seed grant, which the runtime evaluates against the account's real derivation (public) or witness binding (private).
- **Paying twice, fake approvals, threshold.** As before: `MarkExecuted`, `MemberIs`, and the count carried into both guards.

Two subtleties carry the security:

- `Execute` proposes the approval list and its count; the config guard checks the count against the real threshold and the proposal guard checks every listed approval was really recorded. Neither apply sees the other shard, so the *count* is what joins them.
- `Approve` is **commutative**: appending an index if absent settles correctly in any order, so two members' private approvals prepared against the same proposal both land.

### How each kind of member approves

| Member | Transaction | Authorization | Chain sees |
|---|---|---|---|
| Public account | public tx, signs; or private tx, signs | `is_authorized` on the member's account | the member's id and signature, `Approve{member}` |
| Private (secret credential) | private tx, no signature, no private accounts needed (dummies only) | plan hashes the secret from instruction data; the receipt binds it | `MemberIs{index, H(secret)}` and `Approve{member}`: **which slot approved**, nothing about the person |

A private member's approval is a private transaction whose only real content is two public effects. It is replay-safe because its dummy nullifiers enter the nullifier set. It cannot be forged because producing the proof needs the secret, and the secret never leaves the prover. The registered value `H(secret)` is public in the config, but that is a pseudonym, not an account.

If the member wants even the slot hidden, the `MemberIs` guard has to go, and membership must be proven without naming the index: the instruction carries a copy of the member list, the plan asserts `H(secret)` is in it and pins the copy with a guard `MembersHashIs(H(list))` on the config. The approval then records a per-proposal nullifier `H(secret, proposal)` instead of an index, and the threshold check counts distinct nullifiers. Which member approved is then hidden from everyone, including the other members. This is a second `Approve` variant in the same program.

### Placements, and how the wallet lists them

| Config and proposals | Vault | How the wallet lists them |
|---|---|---|
| public accounts (a founder's account, or PDAs) | public PDA under `vault_seed` | `Public(..)`, `PublicNoSign(..)` |
| public | private PDA under a group key | vault as `PrivatePdaShared { authority: multisig, seed: vault_seed, nsk, vpk, identifier }`; the `Execute` is a private tx by a group-key holder |
| group-held private accounts | private PDA under the same group key | everything as `PrivateShared` / `PrivatePdaShared`; every action is a private tx; approvals serialize |
| private | public | legal but pointless: the vault's movements are public anyway and the board hides only the member list |

A private vault means the balance is hidden and so is every payment to a private recipient. The cost: only a group-key holder can build the execution, and the group key gives every member the *ability* to update the vault's note, so the program's seed check is what keeps a single member from spending without approvals. That check is in `Execute`'s plan, in the proof. It holds.

### Recipient placement

A `PayNative` to a private recipient needs the recipient's `(npk, vpk)` and a fresh identifier. If the proposal stores them and the proposal is public, the recipient key is public. Store a **commitment** `H(npk ‖ vpk ‖ identifier)` in the action instead, and have `Execute` carry the preimage in instruction data; the plan recomputes the commitment and the `MarkExecuted` guard compares actions. Public executors then cannot execute (they lack the preimage), which is fine: the proposer or a member does.

## Everything private

The same program, with config, proposals and vault all placed in group-held private accounts (`PrivateShared` for the board, `PrivatePdaShared` for the vault), and every member acting through private transactions with the group's `nsk`.

- Approve: `Update` of the board account with `Effect::Approve{member}` applied **in the proof**. Nothing public at all.
- Execute: `Update` of the board and of the vault, chained `custody_transfer` to the recipient.

Leaks: nothing, until a payment reaches a public account. Even that the multisig exists is not on chain (use a shadow program and it is not even a claim).

Cost: **approvals serialize**. Every approval spends the board's current commitment, so members must approve one after another, each syncing the other's note first. Two simultaneous approvals collide and one is refused. For a small, coordinating group that is acceptable; for a DAO it is not. There is also no threshold safety from the key model itself: every member holds the full group key and could, with a malicious wallet, write any note; only the program's rules, enforced in the proof, stop that, which is exactly as strong as the public case.

## Private members, public vault, hidden approvals

A hybrid for "a public treasury run by an anonymous committee": the public board with the nullifier-based `Approve` variant and a public vault. The world sees a proposal, a growing count of anonymous approvals, and an execution. It never learns the committee's identities, only their number.

## Interoperability matrix

| Members | Board | Vault | Concurrency | Hidden | Visible |
|---|---|---|---|---|---|
| Pub | Pub | Pub | full | nothing | everything (classic multisig) |
| Priv | Pub | Pub | full | identities | slots or count, actions, amounts |
| mixed | Pub | Pub | full | private members' identities | the rest |
| Priv | Pub | Priv (group) | approvals full, execution one at a time | identities, balance, private payments | that a proposal exists and was executed |
| Priv | Priv (group) | Priv (group) | one member at a time | everything until a public payment | nothing |
| Pub | Priv | any | one at a time | the board | member signatures on private txs (they still sign) |

The last row shows a trap: a public member approving on a private board still signs the private transaction, so their participation is public even though the board is not. Public credentials belong with public boards.

## What leaks, summary

- Public board: the proposal's action (recipient, amount) is public from `Propose`; approvals reveal slots (or only a count, with nullifiers); execution reveals the transfer if the recipient is public.
- Private board: nothing, except public-side payments.
- All designs: a private member's approval is a private transaction with no real notes. If the wallet ever stops padding to seven, such transactions become recognizable by having only dummies. Today they are not.

## Ideas

- **Weighted thresholds** and **time-locked execution** (a clock guard `TimestampAtLeast(proposed_at + delay)`) fit the public board directly.
- **Spending limits without approval** for small amounts: a per-period allowance in the config, checked by a clock guard and a counter effect.
- **Social recovery** of a private account: the account is a private PDA of a recovery program under the owner's key; the program's `Execute` can re-initialize a replacement slot under a new key once `k` guardians approve. The old note is not "taken" (nobody can update it without the owner's `nsk`); the program simply moves what it controls.
- **What does not work:** a private board with concurrent approvals (nullifier contention), and a private vault spendable by a public-only executor (someone must hold the group `nsk` to build the witness).
