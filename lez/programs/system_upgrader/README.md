# system_upgrader

Upgrades and installs LEZ's system programs (`clock`, `fee`, `bridge`, …), each change approved by
a threshold of the sequencer committee.

## Changing a system program

The three possible changes that a sequencer committee can apply:

- **`schedule`**: switch `name` to new code at block `activation_height`.
- **`cancel`**: withdraw `name`'s pending upgrade, if it is exactly this one.
- **`install`**: deploy a new system program `name`.

**Workflow:**

1. Anyone can upload the ELF as a segment chain. No header is written for this segment chain. The
   first segment's account ID is the `first_segment` of the proposal.
2. The sequencer committee agree off-chain on the exact proposal (change type
   (`schedule`/`cancel`/`install`), name, `first_segment`, image ID, whether a `schedule` or
   `install` leaves the program immutable, and activation height for a `schedule` or `cancel`).
   Each member checks the image ID against their own reproducible build.
3. Each member signs the proposal offline (`approve_system_change`) and submits the approval to any
   sequencer, which gossips it to the rest.
4. Once a threshold of approvals is pooled, the next block producer includes the change in its
   block. An `install` or `cancel` takes effect in that block. A `cancel`'s activation height only
   identifies the pending upgrade it withdraws.
5. A `schedule` only records the upgrade as pending. The chain enforces it: the block producer at
   its activation height must apply it. Otherwise, the peers reject the block.

## Not upgradable on-chain

`system_upgrader` is seeded immutable at genesis, so nothing on-chain can change it. Only a hard
fork can, and it must also account for its mirror commitment, which stays in the commitment set.

Until then, the code around it must keep accepting the messages it sends (pinned by
`system_upgrader_loader_message_encodings_are_pinned` and `verify_approvals_encodings_are_pinned`)
and keep the encodings of `system_upgrader_core` it was built with.
