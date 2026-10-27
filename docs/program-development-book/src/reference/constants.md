# Protocol constants and limits

| Constant | Value | Where | Meaning |
|---|---|---|---|
| `DATA_MAX_LENGTH` | 100 KiB | `lee_core::account::data` (v0.3.1) | maximum shard size. Removed under actors, where actor state has no cap of its own |
| `MAX_NUMBER_CHAINED_CALLS` | 10 | `lee_core::program` | chained calls per transaction, root excluded |
| `MAX_PROGRAM_SEGMENTS` | 20 | `lee_core::program` | segments in a program's bytecode chain |
| `MAX_SEGMENT_DATA_LEN` | 96 KiB | `program_loader_core` | recommended bytes per segment |
| `MAX_CIPHERTEXT_PADDING` | 8 KiB | `lee_core::encryption` | maximum note pad a prover may request |
| `CIPHERTEXT_PAD_SIZE` | 512 B | `wallet::account_manager` | pad the wallet uses |
| `MAX_PRIVATE_ACCOUNTS` | 7 | `wallet::account_manager` | private actions per transaction, after padding |
| `ML_KEM_768_CIPHERTEXT_LEN` | 1088 B | `lee_core::encryption` | `epk` size per note |
| `ViewingPublicKey::LEN` | 1184 B | `lee_core::encryption` | `vpk` size |
| `PrivateAccountKind::HEADER_LEN` | 97 B | `lee_core::program` | note header |
| `Identifier` | 32 B, base58 in the CLI | `lee_core::nullifier` | private-account identifier; `Identifier::ZERO`, `Identifier::new([u8; 32])` |
| `DEFAULT_PUBLIC_CYCLE_BUDGET` | 32 M cycles | `lee::program` | budget for fee-exempt public calls |
| `MAX_GAS_EXEC` | 10 M cycles | `fee_core::market` | per-transaction and per-block execution gas cap |
| `TARGET_GAS_EXEC` | 5 M cycles | `fee_core::market` | block target |
| `MAX_GAS_STOR` / `TARGET_GAS_STOR` | 1 M / 500 K bytes | `fee_core::market` | storage gas caps (transaction bytes) |
| `BASE_FEE_EXEC_MIN` / `BASE_FEE_STOR_MIN` | 8 / 8 | `fee_core::market` | floor prices |
| `D_EXEC` / `D_STOR` | 8 | `fee_core::market` | ±12.5% max base-fee move per block |
| `SMOOTHING_WINDOW` | 50 blocks | `fee_core::market` | producer payout smoothing |
| `PRIVATE_VERIFY_GAS` | 409,764 | `fee_core::market` | provisional private verification gas (not charged today) |
| `GENESIS_BLOCK_ID` | 1 | `lee_core` | first block |
| Clock cadence | 1 / 10 / 50 blocks | `clock_core` | the three clock accounts |
| Timestamp unit | milliseconds | `lee_core::Timestamp` | |
| `slash_approval_threshold(n)` | `max(2, ceil(2n/3))` | `sequencer_stake_core` | |

Sequencer stake: an `UnstakeRequest` names `requested_at` (a block at most `UNSTAKE_REQUEST_WINDOW` = 16 blocks ahead) and `FinalizeUnstake` may land only after `ChannelParams::exit_delay` blocks (`DEFAULT_SEQUENCER_EXIT_DELAY` = 100).

Interim policies to re-check when they change: private transactions are fee-exempt (`lez/chain_state/src/classify.rs`); bridge withdrawals are disabled (`lez/programs/bridge/src/main.rs`); the AMM charges no swap fee.
