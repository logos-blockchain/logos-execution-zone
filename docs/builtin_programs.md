# Built-in programs

LEZ v0.3 supports the following built-in programs, loaded at genesis. They are immutable and identified by unique `ProgramId` values.

- Authenticated transfer (`AUTHENTICATED_TRANSFER_ID`)
- Token (`TOKEN_ID`)
- AMM (`AMM_ID`)
- Associated Token Account (`ASSOCIATED_TOKEN_ACCOUNT_ID`)
- Clock (`CLOCK_ID`)
- Vault (`VAULT_ID`)
- Faucet (`FAUCET_ID`)
- Piñata (`PINATA_ID`) — testnet only


### Authenticated transfer program

Moves native tokens from a source account to a destination account, requiring the source account to be authorized. Has two instruction variants:

- `Initialize` with a single pre-state: claims the pre-state account (which must be `Account::default()`) on behalf of the caller. Authorization is enforced by the runtime when processing `Claim::Authorized`.
- `Transfer { amount }` with two pre-states `[sender, recipient]`: standard transfer. Sender must be authorized. The recipient is claimed only if its `program_owner` is currently the default — pre-existing accounts owned by other programs keep their owner.

```rust
pub enum Instruction {
    /// Initialize a new account under the ownership of this program.
    /// Required accounts: `[account_to_initialize]`.
    Initialize,

    /// Transfer `amount` of native balance from sender to recipient.
    /// Required accounts: `[sender, recipient]`.
    Transfer { amount: NativeToken },
}

fn transfer_authorized(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction: Instruction,
) -> (Vec<AccountWithMetadata>, Vec<AccountPostState>, Vec<ChainedCall>) {
    let post_states = match instruction {
        Instruction::Initialize => {
            let [account_to_claim] = <[_; 1]>::try_from(pre_states.clone()).unwrap();
            assert_eq!(account_to_claim.account, Account::default());
            vec![AccountPostState::new_claimed(
                account_to_claim.account.clone(),
                Claim::Authorized,
            )]
        }
        Instruction::Transfer { amount } => {
            let [sender, recipient] = <[_; 2]>::try_from(pre_states.clone()).unwrap();
            assert!(sender.is_authorized, "Sender must be authorized");

            let mut sender_post = sender.account.clone();
            sender_post.balance = sender_post.balance.checked_sub(amount).unwrap();

            let mut recipient_post = recipient.account.clone();
            recipient_post.balance = recipient_post.balance.checked_add(amount).unwrap();

            vec![
                AccountPostState::new(sender_post),
                AccountPostState::new_claimed_if_default(recipient_post, Claim::Authorized),
            ]
        }
    };

    (pre_states, post_states, vec![])
}
```

### Piñata program

Distributes a fixed prize of native tokens to the account that provides the correct solution to a proof-of-work–style challenge stored in the pinata account's data. Used for native token distribution during testing.

The pinata account's `data` is a 33-byte buffer: `[difficulty (1 byte), seed (32 bytes)]`. A solution `s: u128` is valid iff the leftmost `difficulty` bytes of `SHA256(seed || s_le_bytes)` are all zero. After a winning solution the seed is rotated to `SHA256(seed)`.

```rust
const PRIZE: NativeToken = 150;

/// Instruction data: u128 solution.
fn pinata(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    solution: u128,
) -> (Vec<AccountWithMetadata>, Vec<AccountPostState>, Vec<ChainedCall>) {
    let [pinata, winner] = <[_; 2]>::try_from(pre_states.clone()).unwrap();

    let challenge = Challenge::parse(&pinata.account.data);
    if !challenge.validate_solution(solution) {
        // No valid solution: the program exits without writing any output,
        // causing the sequencer to reject the transaction entirely.
        return;
    }

    let mut pinata_post = pinata.account.clone();
    let mut winner_post = winner.account.clone();
    pinata_post.balance = pinata_post.balance.checked_sub(PRIZE).unwrap();
    pinata_post.data = challenge.next_data().to_vec().try_into().unwrap();
    winner_post.balance = winner_post.balance.checked_add(PRIZE).unwrap();

    let post_states = vec![
        // Pinata is claimed if its program_owner is currently default
        // (so the very first invocation locks it under the pinata program).
        AccountPostState::new_claimed_if_default(pinata_post, Claim::Authorized),
        AccountPostState::new(winner_post),
    ];

    (pre_states, post_states, vec![])
}
```

### Token program

Manages user-defined fungible and non-fungible tokens. Each token consists of a *definition account* (immutable rules) and one or more *holding accounts* (per-owner balances). Optional metadata is stored in a separate metadata account.

```rust
pub enum TokenDefinition {
    Fungible {
        name: String,
        total_supply: u128,
        metadata_id: Option<AccountId>,
    },
    NonFungible {
        name: String,
        printable_supply: u128,
        metadata_id: AccountId,
    },
}

pub enum TokenHolding {
    /// Balance of a fungible token.
    Fungible { definition_id: AccountId, balance: u128 },
    /// Master holding of an NFT collection. `print_balance` is the number of printable copies left.
    NftMaster { definition_id: AccountId, print_balance: u128 },
    /// A printed instance of an NFT.
    NftPrintedCopy { definition_id: AccountId, owned: bool },
}

pub struct TokenMetadata {
    pub definition_id: AccountId,
    pub standard: MetadataStandard,
    pub uri: String,
    pub creators: Vec<...>,
    pub primary_sale_date: u64,
}
```

**Instructions:**

- `Transfer { amount_to_transfer: u128 }` — accounts: `[sender_holding, recipient_holding]`. Sender must be authorized. Recipient is auto-initialized when `Account::default()`. NFT master copies and printed copies are also transferred via this instruction (with `amount_to_transfer == print_balance` for masters and `1` for printed copies). The recipient holding is claimed only if its `program_owner` is currently default (`new_claimed_if_default`).
- `NewFungibleDefinition { name: String, total_supply: u128 }` — accounts: `[definition_target, holding_target]`. Both must be `Account::default()`. The definition holds the supply; the holding is initialized to `total_supply`. Both are claimed (`new_claimed`).
- `NewDefinitionWithMetadata { new_definition, metadata }` — accounts: `[definition_target, holding_target, metadata_target]`. Same as above plus a metadata account; supports both fungible and non-fungible variants. All three are claimed.
- `InitializeAccount` — accounts: `[definition, account_to_initialize]`. Creates a zero-balance holding bound to `definition.account_id`. Only the holding is claimed.
- `Burn { amount_to_burn: u128 }` — accounts: `[definition, user_holding]`. Holding must be authorized. Decreases both `holding.balance` and `definition.total_supply`. Neither account is claimed.
- `Mint { amount_to_mint: u128 }` — accounts: `[definition, holding_target]`. Definition must be authorized. Increases both `holding.balance` and `definition.total_supply`. Holding is claimed if currently default.
- `PrintNft` — accounts: `[nft_master_holding, nft_printed_copy_target]`. Decrements `print_balance` on the master and produces a new printed copy holding.

All Token Program operations check that the `definition_id` referenced by each holding matches the supplied definition account.

### AMM program

Manages liquidity pools for token pairs; supports pool initialization, add/remove liquidity, and swaps. Pools are primarily intended to be public, in which case each `(token_a, token_b)` pair yields a unique pool. In private state a pool is scoped to the user's `(Npk, identifier)` namespace, so each pair produces one pool per namespace.

**Pool Definition Account:**

```rust
struct PoolDefinition {
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
    vault_a_id: AccountId,
    vault_b_id: AccountId,
    liquidity_pool_id: AccountId,
    liquidity_pool_supply: u128,
    reserve_a: u128,
    reserve_b: u128,
    fees: u128,
    active: bool,
}
```

**Initialize pool:**

Creates the pool definition, two vaults (one per token), and an LP token definition. Deposits the initial liquidity through chained Token Program calls.

**Add liquidity:**

Deposits tokens into the vaults in proportion to the current reserves. Mints LP tokens to the depositor through chained Token Program calls. The LP amount is calculated as:

```rust
let delta_lp = min(
    pool_supply * actual_amount_a / reserve_a,
    pool_supply * actual_amount_b / reserve_b,
);
```

**Remove liquidity:**

Burns LP tokens and withdraws proportional amounts of each token from the vaults:

```rust
let withdraw_a = (reserve_a * amount_lp) / pool_supply;
let withdraw_b = (reserve_b * amount_lp) / pool_supply;
```

**Swap:**

Executes a constant-product AMM swap. For a deposit of `amount_in` of one token:

```rust
let amount_out = (reserve_out * amount_in) / (reserve_in + amount_in);
```

All AMM operations use chained calls to the Token Program for the actual token movements between user holding accounts and vault accounts. PDAs are used to authorize vault transfers.

### Associated Token Account (ATA) program

Provides a deterministic, per-`(owner, token_definition)` holding-account address derived as a public PDA of the ATA program. Removes the need for users to manage explicit token-holding account IDs; given an owner account and a token definition, anyone can compute the corresponding ATA address.

```rust
pub fn compute_ata_seed(owner_id: AccountId, definition_id: AccountId) -> PdaSeed {
    PdaSeed::new(SHA256(owner_id || definition_id))
}

pub fn get_associated_token_account_id(ata_program_id: &ProgramId, seed: &PdaSeed) -> AccountId {
    AccountId::for_public_pda(ata_program_id, seed)
}
```

**Instructions:**

- `Create { ata_program_id }` — accounts: `[owner, token_definition, ata_account]`. Creates the ATA for `(owner, definition)` if it does not already exist (idempotent). Chains to the Token Program's `InitializeAccount` to populate the holding data.
- `Transfer { ata_program_id, amount }` — accounts: `[owner, sender_ata, recipient_holding]`. Owner must be authorized. The ATA program verifies `sender_ata.account_id == for_public_pda(ata_program_id, compute_ata_seed(owner.id, definition_id))`, then chains to the Token Program's `Transfer`, passing the ATA seed in `pda_seeds` to authorize the ATA inside the Token Program.
- `Burn { ata_program_id, amount }` — accounts: `[owner, holder_ata, token_definition]`. Same PDA-seed authorization mechanism as `Transfer`; chains to the Token Program's `Burn`.

The `ata_program_id` is passed as part of the instruction (rather than read from `self_program_id`) so it can be precomputed by callers without invoking the program.

### Clock program

Records the current block ID and timestamp into three dedicated clock accounts, updated at different cadences (every 1, 10, and 50 blocks). Programs that need recent timestamps can read whichever granularity matches their needs.

```rust
pub const CLOCK_01_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(*b"/LEZ/ClockProgramAccount/0000001");
pub const CLOCK_10_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(*b"/LEZ/ClockProgramAccount/0000010");
pub const CLOCK_50_PROGRAM_ACCOUNT_ID: AccountId = AccountId::new(*b"/LEZ/ClockProgramAccount/0000050");

pub struct ClockAccountData {
    pub block_id: BlockId,
    pub timestamp: Timestamp,
}
```

The clock accounts are created at genesis and assigned `program_owner = clock_program_id`, so no claiming is required at runtime. The Clock Program is invoked **exclusively by the sequencer as the last transaction in every block**: users cannot invoke it directly. Its single instruction is the new block's `Timestamp`.

On execution, the program reads `block_id` from the `01` account, increments it, and updates each of the three clock accounts only when `new_block_id` is a multiple of the corresponding cadence.

### Vault program

Provides a native-token escrow via per-user vault PDAs. Each user's vault is a PDA of the Vault program keyed by the user's account ID. Two instructions:

- `Transfer { recipient_id, amount }` — accounts: `[sender, recipient, recipient_vault_pda]`. Sender must be authorized. Transfers `amount` native tokens from `sender` to the vault PDA of `recipient_id`. The vault PDA is claimed on first use.
- `Claim { amount }` — accounts: `[owner, owner_vault_pda]`. Owner must be authorized. Withdraws `amount` native tokens from the owner's vault PDA back to the owner's account.

Vault PDA seed derivation:

```rust
const VAULT_SEED_DOMAIN_SEPARATOR: &[u8; 32] = b"/LEZ/v0.3/VaultSeed/00000000000/";

pub fn compute_vault_seed(owner_id: AccountId) -> PdaSeed {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(VAULT_SEED_DOMAIN_SEPARATOR);
    bytes[32..64].copy_from_slice(&owner_id.to_bytes());
    PdaSeed::new(sha256(bytes))
}

pub fn compute_vault_account_id(vault_program_id: ProgramId, owner_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&vault_program_id, &compute_vault_seed(owner_id))
}
```

### Faucet program

Manages the system faucet, a pre-funded account used to distribute native tokens. The faucet account is a public PDA of the Faucet program, created at genesis. One instruction:

- `Transfer { vault_program_id, recipient_id, amount }` — accounts: `[faucet_pda, recipient_vault_pda]`. Transfers `amount` native tokens from the system faucet to the vault PDA of `recipient_id`. User-submitted transactions cannot invoke the Faucet program directly; only sequencer-originated transactions may do so.

Faucet PDA seed and account derivation:

```rust
const FAUCET_SEED_DOMAIN_SEPARATOR: [u8; 32] = *b"/LEZ/v0.3/FaucetSeed/0000000000/";

pub fn compute_faucet_seed() -> PdaSeed {
    PdaSeed::new(FAUCET_SEED_DOMAIN_SEPARATOR)
}

pub fn compute_faucet_account_id(faucet_program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&faucet_program_id, &compute_faucet_seed())
}
```



