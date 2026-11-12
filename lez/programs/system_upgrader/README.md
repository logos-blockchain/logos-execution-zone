# system_upgrader

Upgrades and installs LEZ's system programs (`clock`, `fee`, `bridge`, …), each change approved by
a threshold of the sequencer committee.

## Not upgradable on-chain

`system_upgrader` is seeded immutable at genesis, so nothing on-chain can change it. Only a hard
fork can, and it must also account for its mirror commitment, which stays in the commitment set.

Until then, the code around it must keep accepting the messages it sends (pinned by
`system_upgrader_loader_message_encodings_are_pinned` and `verify_approvals_encodings_are_pinned`)
and keep the encodings of `system_upgrader_core` it was built with.
