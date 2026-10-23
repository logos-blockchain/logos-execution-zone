# Account-id derivations

All ids are 32 bytes. All hashes are SHA-256. Each derivation starts with a 32-byte domain prefix so that ids of different kinds cannot collide.

## Account ids

| Kind | Inputs after the prefix | Prefix begins | Source |
|---|---|---|---|
| Public, key-owned | the public key | `/LEE/v0.3/AccountId/Public/` | `lee/state_machine/src/signature/public_key.rs` |
| Public PDA | program account id, seed | `/LEE/v0.2/AccountId/PDA/` | `AccountId::for_public_pda` |
| Private, regular | nullifier public key, viewing public key | `/LEE/v0.3/AccountId/Private/` | `lee/state_machine/core/src/nullifier.rs` |
| Private PDA | program account id, seed, nullifier public key, viewing public key | `/LEE/v0.3/AccountId/PrivatePDA/` | `AccountId::for_private_pda` |
| Blinded address | account id, 32-byte factor | `/LEE/v0.3/AccountId/Blinded/` | `AccountId::blinded` |
| Builtin program | the program's name | `/LEE-BuiltinProgram/v1/AccountId` | `AccountId::from_builtin_program_name` |
| Shadow program | the image id | `/LEE/v0.3/AccountId/Shadow/` | `AccountId::for_shadow_program` |
| Immutable-program mirror | the program header's account id | `/LEE/v0.3/AccountId/ImmutMirror/` | `AccountId::for_immutable_mirror` |

The functions without a file are in `lee/state_machine/core/src/program/mod.rs`.

## Fixed ids

| Id | Value | Meaning |
|---|---|---|
| `NATIVE_TOKEN_PROGRAM_ID` | 32 zero bytes | the native token |
| `PROGRAM_LOADER_ACCOUNT_ID` | 32 bytes of `0xFE` | the program loader |
| `CLOCK_01_PROGRAM_ACCOUNT_ID` | `/LEZ/ClockProgramAccount/0000001` | the every-block clock account |
| `CLOCK_10_PROGRAM_ACCOUNT_ID` | `/LEZ/ClockProgramAccount/0000010` | every 10th block |
| `CLOCK_50_PROGRAM_ACCOUNT_ID` | `/LEZ/ClockProgramAccount/0000050` | every 50th block |

## What follows from the derivations

- **A public PDA is the same for everyone.** Program and seed fix it.
- **A private PDA is per key holder.** Two groups using the same program and seed get different accounts, because their keys differ.
- **A blinded address is per factor.** One account has as many addresses as its owner cares to make, and they are unlinkable without the factors.
- **A program deployed twice has two ids**, so two disjoint families of PDAs.

## Group keys

A group secret derives keys for shared accounts (`lee/key_protocol/src/key_management/group_key_holder.rs`):

| For | Derived from |
|---|---|
| a group-owned private PDA | the secret, the program's image id, the seed |
| a shared regular account | the secret, a derivation seed |

The two use different domain prefixes. Every member derives the same keys, so the same account ids.
