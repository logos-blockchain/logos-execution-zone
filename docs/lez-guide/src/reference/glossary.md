# Glossary

**Account.** A nonce and a map from program ids to actor states.

**Actor.** One program's state on one account: the pair `(account_id, program_account_id)`. Every message is addressed to an actor.

**Actor state.** The bytes an actor holds. Only that actor's handler reads and writes them.

**Address.** An id at which a private account receives messages: its account id, or a blinded form of it.

**Admission.** The check that a public account may receive a message: it exists, it signed, evidence for it is supplied, or the sender granted its seed.

**Authorization.** The `is_authorized` flag: the receiving account's owner signed or supplied the spending key, or a program granted the account's seed.

**Blinded address.** A hash of an account id and a secret factor. A pseudonym for a private account.

**Boundary.** In a private transaction, the ordered list of messages that crossed between private and public actors. Published in the clear.

**SyncMessage.** A message delivered immediately, in the same transaction. If it fails, the transaction fails. It returns no value.

**AsyncMessage.** A message that may wait. Delivered immediately when the transaction can run the receiver, stored on chain otherwise.

**Collecting.** Building a private transaction whose root is a stored message, so that the receiving handler runs.

**Commitment.** A hash published in place of a private account's contents, or of a stored message.

**Dry run.** The wallet's run of the whole of a private transaction on its own machine, outside any proof, against a snapshot of public actor state. It yields the messages that will cross, the promotions selected and the sender presentations used, and the proof is built against all three. It meters cycles against the public cycle budget, so an over-budget transaction fails here rather than at settlement, but it does not report the count and it does not compute a fee. A public transaction has no dry run. Both of those are changing: the work that makes private transactions pay also turns this into a priced dry run a wallet can call for either kind of transaction.

**Echo.** A handler's proof includes the input it ran on, so the engine can check it was the right input.

**Group secret.** A shared secret from which a group derives the keys of accounts it owns together.

**Handler.** A program's one function: input and message in, response out.

**Image id.** The hash of a program's binary.

**LEE, LEZ.** The execution environment, and the zone built on it.

**Mailbox.** The set of stored messages on chain.

**Nullifier.** A value published when a version of a private account, or a stored message, is used up. It prevents using it twice.

**PDA.** Program-derived account. An account with no key, controlled by a program through a seed.

**Poke.** A message anyone may send that moves a public actor forward by its own rules.

**Private part, public part.** The two halves of a private transaction: private handlers proven on the user's machine, public handlers run by the sequencer.

**Program.** A deployed RISC Zero guest binary, identified by the account id it is deployed at.

**Promotion.** Delivering an AsyncMessage inside its own transaction because the submitter can run the receiver.

**Proof-carrying message.** A message from a private actor to a public actor of the same program. The public side trusts it because its own code produced it inside a proof.

**Publication.** A stored message: clear when the sender was public, sealed when the sender was private.

**Recovery binding.** An on-chain record that registers an address and lets its owner recognise it.

**Root.** The one message a transaction delivers first.

**Seat.** A participant's own actor of a shared program, through which they speak to the program's shared actor.

**Seed grant.** A program authorizing one of its PDAs by attaching the seed to a SyncMessage.

**Sealed async message.** A stored message encrypted to its recipient.

**Transition.** A handler's input together with its response. What a handler's proof commits to.

**Validity window.** A range of blocks or timestamps outside which a transaction is invalid.
