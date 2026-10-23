# Account-id derivations

All hashes are SHA-256 over a domain prefix followed by the fields, unless noted. Prefix lengths vary and are not all 32 bytes. Account-id, commitment and nullifier-value prefixes are padded to 32. The key-derivation prefixes in the Keys table below are their natural lengths: `ask` 33, `nsk` and `npk` 29, `vsk` 27. The view tag is 18, `esk` 14 and the note key 20. The two private-nonce rows have no domain prefix at all. `‖` is concatenation. Integers are little-endian, except the key-derivation `index`, which is big-endian to follow BIP-032. Sources: `lee/state_machine/core/src/{program/mod.rs,nullifier.rs,commitment.rs,encryption/mod.rs}`, `lee/state_machine/src/signature/public_key.rs`, `lee/key_protocol/`.

## Account ids

| Kind | Prefix | Fields |
|---|---|---|
| Public, key-held | `/LEE/v0.3/AccountId/Public/` | BIP-340 x-only public key (32) |
| Private, regular | `/LEE/v0.3/AccountId/Private/` | `npk` (32) ‖ `vpk` (1184) ‖ `identifier` (32) |
| Public PDA | `/LEE/v0.2/AccountId/PDA/` | `program_account_id` (32) ‖ `seed` (32) |
| Private PDA | `/LEE/v0.3/AccountId/PrivatePDA/` | `program_account_id` ‖ `seed` ‖ `npk` ‖ `vpk` ‖ `identifier` (32) |
| Shadow program | `/LEE/v0.3/AccountId/Shadow/` | `from_builtin_program(image_id)` (32) |
| Immutable mirror | `/LEE/v0.3/AccountId/ImmutMirror/` | header account id (32) |
| Builtin program | `/LEE-BuiltinProgram/v1/AccountId` | the program's stable name, e.g. `b"clock"`, `b"fee"`, `b"bridge"`, `b"sequencer_stake"`, `b"wrapped_token"` |
| Test-seeded program | none (byte reinterpretation) | image id `[u32; 8]` as 32 LE bytes (`from_builtin_program`, tests only) |
| Genesis segment | `/LEE/v0.3/AccountId/GenesisSeg/` | header id ‖ index (u32) |

Reserved: native token program `[0; 32]`, program loader `[0xFE; 32]`, clock accounts `/LEZ/ClockProgramAccount/0000001` etc. (literal bytes).

## Keys

| Key | Derivation |
|---|---|
| `ask` | `SHA256("/LEE-Keys/v1/Authorization/Secret" ‖ ssk ‖ index_be)` |
| `nsk` | `SHA256("/LEE-Keys/v1/Nullifier/Secret" ‖ ask)` |
| `npk` | `SHA256("/LEE-Keys/v1/Nullifier/Public" ‖ nsk)` |
| `vsk = (d, z)` | HMAC-SHA512 over `"/LEE-Keys/v1/Viewing/Secret" ‖ ssk ‖ index` with key `"/LEE-Keys/v1/Viewing/Seed"`, split in two |
| `vpk` | ML-KEM-768 encapsulation key from seed `(d, z)` |
| group `ssk` for a PDA | `SHA256("/LEE/v0.3/GroupKeyDerivation/SSK" ‖ gms ‖ image_id ‖ seed)` |
| group `ssk` for a shared account | `SHA256("/LEE/v0.3/GroupKeyDerivation/SHA" ‖ gms ‖ derivation_seed)` |

## Commitments, nullifiers, notes

| Value | Derivation |
|---|---|
| Commitment | `SHA256("/LEE/v0.3/Commitment/" ‖ account_id ‖ SHA256(borsh(account)))` |
| Init nullifier | `SHA256("/LEE/v0.3/Nullifier/Initialize/" ‖ account_id)` |
| Update nullifier | `SHA256("/LEE/v0.3/Nullifier/Update/" ‖ commitment_pre ‖ nsk)` |
| Dummy nullifier | `SHA256("/LEE/v0.3/Nullifier/Dummy/" ‖ seed)` |
| Dummy commitment | `SHA256("/LEE/v0.3/Commitment/Dummy/" ‖ nullifier ‖ seed)` |
| Private nonce, init | first 16 bytes of `SHA256(account_id ‖ 0^32)` |
| Private nonce, update | first 16 bytes of `SHA256(nsk ‖ nonce_le ‖ 0^16)` |
| View tag | `SHA256("/LEE/v0.3/ViewTag/" ‖ npk ‖ vpk)[0]` |
| Ephemeral secret | `SHA256("/LEE/v0.3/esk/" ‖ account_id ‖ random_seed ‖ nonce)` |
| Note key | `SHA256("LEE/v0.3/KDF-SHA256/" ‖ shared_secret ‖ nullifier)`, ChaCha20 with zero IV |
| Note plaintext | 97-byte `PrivateAccountKind` header (`0x00 ‖ identifier(32) ‖ 0^64` or `0x01 ‖ program(32) ‖ seed(32) ‖ identifier(32)`) ‖ borsh(account), zero-padded to the pad length |

## Program-specific seeds shipped in the zone

| Program | Seed |
|---|---|
| ATA | `SHA256(owner ‖ definition ‖ token_program)` |
| AMM pool | `SHA256(max(def_a, def_b) ‖ min(def_a, def_b) ‖ token_program)` |
| AMM vault | `SHA256(pool ‖ definition)` |
| AMM LP definition | `SHA256(pool ‖ 0^32)` |
| Bridge | `/LEZ/v0.3/BridgeSeed/0000000000/` |
| Bridge deposit receipt | `SHA256("/LEZ/v0.3/BridgeDepositReceipt/0" ‖ op_id)` |
| Fee state / escrow / inbox | `/LEZ/v0.3/FeeSeed/{State,Escrow,Inbox}/…/` |
| Sequencer-stake config | `/LEZ/v0.3/MinSequencerStake/0000` |
| Stake funds | the ownership account id itself |
| Outbox slot | `SHA256("/LEZ/v0.3/CrossZoneOutbox/00001/" ‖ emitter ‖ zone ‖ ordinal)` |
| Inbox source marker | `SHA256("/LEZ/v0.3/CrossZoneSource/00000/" ‖ zone ‖ src_program)` |

Convention for your own seeds: a 32-byte, versioned, program-specific domain string, hashed with the fields. Never reuse a domain across programs, and bump the version when the field list changes.
