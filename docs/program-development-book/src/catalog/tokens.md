# Tokens, NFTs and associated accounts

The token program and the associated-token-account program ship with the zone. This entry reads them as case studies: what they do, how their design follows the pattern language, and what each public/private placement of their accounts means.

Sources: `logos-blockchain/lez-programs: programs/token/`, `logos-blockchain/lez-programs: programs/ata/`, tutorials in `docs/LEZ testnet v0.1 tutorials/`. Both programs moved out of this repository. The token program is deployed from there on the legacy testnet; the ATA program is not in that deployment record.

## The token program

### Accounts

| Account | Shard | Contents |
|---|---|---|
| Definition | token program's shard on any account | `TokenDefinition::Fungible { name, total_supply, metadata_id }` or `NonFungible { name, printable_supply, metadata_id }` |
| Holding | token program's shard on any account | `TokenHolding::Fungible { definition_id, balance }`, `NftMaster { definition_id, print_balance }` or `NftPrintedCopy { definition_id, owned }` |
| Metadata | token program's shard | `TokenMetadata { definition_id, standard, uri, creators, .. }` |

A definition *is* its account id. There is no registry; a token is identified by the address of its definition account, and holdings name it.

### Instructions

| Instruction | Accounts | Authorization | Effects |
|---|---|---|---|
| `NewFungibleDefinition` / `NewDefinitionWithMetadata` | definition (empty), holding (empty), [metadata] | none: creating into empty shards | `Create(bytes)` on each; apply refuses non-empty |
| `InitializeAccount { kind }` | definition, holding | holding must be authorized if non-empty | `CheckHoldingKind(kind)` guard on definition; `InitializeHolding` on holding |
| `Transfer { amount, descriptor }` | sender (authorized), recipient | sender | `Withdraw` on sender, `Deposit` on recipient; a recipient with an empty shard is created |
| `Mint { amount }` | definition (authorized), holding | definition | `MintSupply` on definition, `Deposit` on holding |
| `Burn { amount, kind }` | definition, holding (authorized) | holder | `BurnSupply` on definition, `BurnHolding` on holding |
| `PrintNft { definition_id }` | master (authorized), printed (empty) | master holder | `PrintCopy` on master, `Create` on printed |

Every instruction is a **two-sided binding**: the descriptor or kind crosses from one effect to the other and both applies check it against their own bytes. `Transfer` is the canonical example: the recipient's `Deposit` never sees the sender, so the sender's `Withdraw` is what ties the amount to a real balance.

### Placements

Because the program never reads, every account may be public or private independently. What changes is the transaction shape and the leak:

| Definition | Holding(s) | Works | Notes |
|---|---|---|---|
| Pub | Pub | yes | ordinary |
| Pub | Priv | yes | private balances of a public token: the common case. A private holder transfers privately; a transfer into a public holding shows `Deposit { descriptor, amount }` |
| Priv | Pub | yes | the supply and name are hidden; only the definition's owner can `Mint` (it needs the definition authorized, so a private transaction by the owner). Strangers cannot run `InitializeAccount` or `Burn`, which name the definition, because they cannot supply its witness; holdings come into existence only through `Transfer` from an existing holder or `Mint` by the owner |
| Priv | Priv | yes | a fully private token: existence, supply and every balance hidden; the definition id still appears inside holdings, which are themselves private |

A subtle point in the Priv-definition rows: `Burn` names the definition, so a holder of a private-definition token cannot burn without the owner (the owner's wallet must build the transaction with the definition's witness). A token whose holders should be able to burn independently keeps a public definition.

{{#include ../diagrams/tokens-placements.svg}}

### Creating a token into a private supply account

`wallet token new --definition-account-id Public/… --supply-account-id Private/…` runs `NewFungibleDefinition` as a private transaction: `Create` on the public definition is a deferred effect (the name and supply are public), `Create` on the private holding is applied in the proof. The chain learns a token was created with supply S and that some note received it.

### NFTs

An NFT is a definition with `printable_supply`, a master holding that can `PrintNft` copies, and printed copies whose `owned: bool` flips on transfer. A printed copy in a **private** holding is a privately owned NFT: nobody sees who holds it, and transfers between private accounts are invisible. Proving ownership without transferring is an attestation (see [Tickets, attestations and registries](access-and-attestations.md)).

## Associated token accounts

The ATA program gives every `(owner, definition)` a deterministic holding address and lets the owner spend from it by signing for the owner account alone:

```rust
seed = H(owner_id ‖ definition_id ‖ token_program_id)
ata  = AccountId::for_public_pda(&ata_program_id, &seed)
```

It owns no shard. Every effect it emits is an **inspect** on the token program's shards (`AtaContents`, `DefinitionKind`), and every write happens in a chained call into `token` with the ATA's seed delegated. This is the purest example of a program that is only authority plus guards.

`Create` takes the claimed contents of the ATA (`Empty`, `Intended`, `Squatted`) as a proposal and pins it with an inspect; the comment in `create.rs` explains why taking it on faith would let anyone zeroize a funded ATA. Read that comment; it is the proposal-and-guard discipline stated as an attack.

### Private owners

The tutorial's "ATA with a private owner" uses the owner's **private account id** in the seed. The ATA is still a *public* PDA (the holding is visible), and its seed contains the owner's private id. Anyone who knows or guesses that id can confirm the ATA is theirs; the id itself is not recoverable from the address. The owner spends by a private transaction that authorizes their private account (with `ask`), and the ATA program delegates the seed. What the chain sees: a public holding moving, authorized by a program, with no signature. The owner's identity is a hash preimage away from public.

A fully private variant would use a private PDA family: `for_private_pda(ata_program, H(definition), owner_npk, owner_vpk, Identifier::ZERO)`. The wallet can derive and discover it, the program authorizes it by seed, and nothing about it is public. The shipped ATA does not do this, but nothing in the model prevents it.

## Leaks in token flows

- A transfer into a public holding publishes `Deposit { descriptor, amount }`: the token and the amount.
- A transfer out of a public holding publishes `Withdraw { descriptor, amount }` and the holder is either a signer (public tx) or the sole non-signing public account (private tx with a public sender is impossible without its signature; so a public holding always signs).
- Definition creation publishes name and supply if the definition is public.
- Program claims disclose that the token program ran, always, for any private token transfer (it is a deployed guest, unlike the native token). A token whose transfers should disclose nothing must be a **shadow program** token, which then can only ever have private holdings.

## Ideas

- **Confidential-supply token with public holdings**: private definition, public holdings. Odd but legal: balances visible, total supply not. Mints are private transactions by the owner whose `Deposit` on a public holding shows the amount.
- **Soulbound tokens**: a `Transfer` variant that asserts `sender.account_id == recipient.account_id` never, i.e. a program wrapping `token` that refuses to delegate. Simpler: an NFT whose master holding is a PDA of a program that never chains a transfer.
- **Wrapped native**: a token whose `Mint` is a chained native `custody_transfer` into a vault and whose `Burn` releases it, with a two-sided binding between the supply and the vault balance (inspect the vault's native shard).
- **Token-gated programs**: any program can inspect a holding shard it is handed: `plan.inspect(holding, token_program, Guard::HoldsAtLeast(n))`. For a private holding, the guard runs in the holder's proof and only the guard's *existence* (as a private effect) is hidden; for a public holding it is a public effect that names the holding.
