# Idea catalog: more designs, and what does not work

Short entries. Each names the placement of the state, the pattern it rests on, what the chain sees, and where the model pushes back. "Fits" means it can be built with the current protocol; "strained" means it works with a visible compromise; "does not fit" means a structural limit blocks it, with the reason.

## Payments and money

- **Shielded pool.** Built in. Public→private (`Init` a fresh slot), private→private (native transfer, no claim), private→public (deshield). The anonymity set is every private transfer on the chain. Fits.
- **Consolidation / sweeping.** Seven private accounts per transaction: six sources to zero, one destination. Fits; wallets need a "sweep" command.
- **Split payments / payroll batches.** One private transaction, one payer note, up to six recipient slots. Fits; large batches are several transactions.
- **Recurring payments (pull).** [Streams](streams.md). Fits.
- **Micropayments.** [Payment channels](channels.md): signed vouchers off chain, one redemption on chain. Fits.
- **Recurring payments (push, scheduled).** Does not fit: nothing runs without a transaction. Substitute: pre-signed transactions with validity windows handed to a keeper.
- **Invoices.** The payee publishes `(npk, vpk, identifier)` for one invoice; payment initializes that exact slot; the deterministic init nullifier makes the payment observable by anyone who has the invoice, which is what a payee wants. Fits, and the leak is the feature.
- **Payment requests.** The payee gives the payer an invoice slot and the payer pays it. The request can travel on chain as a note under the payer's key (see private messaging below), but a note is only data: the payer still builds the payment themselves. Fits as an invoice; there is no message a payer can approve as it stands.
- **Inheritance / dead man's switch.** A public vault record with `last_heartbeat_ms`. `Heartbeat` is the owner's: a signature, or for a private owner a secret carried in a **private** transaction (in a public one the secret would be published). `Claim` carries a clock guard `now >= last_heartbeat + period` and pays an heir gated by a secret, who claims into a fresh private slot. Fits; the heir must come and claim.
- **Savings lock.** Funds on a PDA whose only instruction pays a fixed gate after a date (a window). No key can break it early. Fits.
- **Crowdfunding with a threshold.** A public campaign record and vault; backers deposit with a secret-hash gate each; after the deadline either the creator is paid (goal met, balance inspect) or each backer reclaims with their secret. Backers hidden, total public. Fits.
- **Bounties.** A vault that pays whoever presents a preimage. To stop front-running of a public claim, claim in a private transaction (the preimage is instruction data) or commit first. Fits.
- **Gift cards / vouchers.** A private PDA family of the voucher program under the issuer's key holding value, with the seed derived from a secret printed on the card; redemption is a private transaction carrying the secret (pattern 11) that moves the value to the redeemer's slot. Fits: the issuer cannot see who redeemed, only that a card was.
- **Wrapped native token with private supply.** Strained: the vault is public, so the supply is public even if the definition is private.
- **Stablecoin with blacklist.** A token wrapper whose `Transfer` inspects a public blacklist PDA. Fits for public holdings; for private holdings the check runs in the holder's proof against the public list at settlement (the guard names the list, not the holder). A private blacklisted holder simply cannot produce a settling transaction. Fits.
- **Confidential payroll with public totals.** Public stream records, private recipients. See streams. Fits.

## Exchange and markets

- **Fixed-offer AMM.** Shipped. **Limit orders** are prepared offers with windows. Fits.
- **Order book.** Public book PDA with `Place`/`Cancel`/`Fill` where `Fill` proposes a match and the book's apply checks it. Makers' identities can be secret credentials; amounts and prices public. Strained: matching is the taker's job, not the book's; one fill per effect.
- **Dark pool.** Does not fit: matching requires reading both sides' private orders.
- **Batch auctions / uniform clearing.** Does not fit as a program (one shard, one effect at a time); fits as a sequencer or off-chain solver that submits the clearing as public effects.
- **Lending with a price oracle.** Strained: no oracle; a price PDA written by a trusted account can be inspected. Liquidations need someone to submit them.
- **Perpetuals / options.** Same as lending, plus settlement needs a price at expiry, which is a clock-gated read of the oracle PDA. Strained.
- **Prediction markets.** Public pool per outcome; positions private (token holdings); resolution by an oracle account; payouts by private claims. Fits with an oracle.

## Governance

- **Token-weighted voting.** [Voting](voting.md) Design A with weight leaves, or Design B with vote tokens proportional to holdings (snapshot by the organizer). Fits; weights or counts public.
- **Petitions.** One-time claims as in [Tickets, attestations and registries](access-and-attestations.md): each credential signs once, the count is public, the signers are not. Fits.
- **Whistleblower channel.** The source writes a note into a slot under the newsroom's published key (see private messaging below) and includes a one-time receive key for the reply. Fits.
- **Timelocked governance actions.** Public board plus clock guard. Fits.
- **Treasury multisig, anonymous signers.** [Multisig](multisig.md) Design C. Fits.
- **Quorum with private membership size.** Does not fit: the threshold check needs the size, in a public config.

## Identity and access

- **Tickets, credentials, attestations, registries, airdrops.** See [Tickets, attestations and registries](access-and-attestations.md). Fits.
- **Age or KYC gating of a program.** The program inspects a credential PDA of the user in the user's private transaction: the guard runs in the proof, the chain sees `Attested(claim)`. Fits.
- **Revocable credentials.** Strained: revocation lists must be public.
- **Private reputation with public leaderboard.** Reputation in private PDAs; the leaderboard shows tags and scores the holders choose to post. Fits.
- **Sybil resistance via RLN.** [Rate-limiting nullifiers](rln.md). Fits.

## Games and social

- **LeZork.** [Text adventure](lezork.md). Fits.
- **Battleship and other answer-truthfully games.** [Battleship](battleship.md): the answer is a guard on the answering player's private shard, so no reveal phase is needed. Fits.
- **Space game with private ships and radio.** [Deep Space Radio](radio.md). Fits, at one proof per action.
- **Treasure hunt.** Each clue is a fresh private slot under the key of whoever solved the previous one. Fits.
- **Secret Santa.** Each participant publishes a one-time receive key; a public draw (commit-reveal among participants) assigns keys; gifts are private transfers to slots under those keys. Fits; the draw is the hard part, as with any randomness.
- **Commit-reveal games (rock-paper-scissors, poker hands).** Commitments are private accounts; reveals are public effects with guards on the private shard. Fits for reveal-based games. Hidden-information games where a third party must act on hidden state (a dealer) need a group key or a trusted dealer.
- **Lotteries.** Does not fit honestly: no randomness. Commit-reveal among participants (each contributes a secret; the winner is determined from the XOR after all reveal; non-revealers forfeit a bond) is the substitute. Fits, with the bond.
- **Chess / turn-based between two.** A public board PDA with `Move` checked by the apply, players as secret credentials for anonymity. Fits. Fully private (group key board): fits, turn-based is single-writer anyway.
- **Private messaging.** A note is an encrypted blob only the recipient decrypts: any program can write bytes into a fresh private slot under the recipient's key. The chain sees a note. Fits, with the 512-byte pad (larger messages are recognizable by size) and the view-tag correlation.
- **Social graph, private follows.** A follow is a private PDA of the graph program under the follower's key; the followee learns of it only if told. Fits, and nothing aggregates it: counts of followers cannot be public without each follow being a public effect.

## Infrastructure

- **Name service.** Registry chapter. Fits.
- **On-chain package registry / program directory.** Public PDAs keyed by name pointing at program account ids and image ids; `program_loader` headers already carry the image id. Fits.
- **Upgradeable programs with timelock.** A mutable header whose `UpdateHeader` goes through a governance program that owns the header account as a PDA. Fits: the loader requires the header target to be authorized, and a program can authorize its own PDA in a chained call... except the loader **cannot be chained into privately** and the chained-call path into the loader in a public transaction is allowed (the loader is a program like any other for `ChainedCall` purposes, resolved by `PROGRAM_LOADER_ACCOUNT_ID`). Verify this in a test before relying on it.
- **Cross-zone bridges.** `bridge_lock` and `wrapped_token` ship. Any cross-zone target must pin its caller and its source marker. Fits; public only.
- **Oracles.** A price PDA written by a signer, or a committee via multisig. The trust is explicit. Fits.
- **Keepers.** Anyone can submit prepared transactions; programs that need periodic action (liquidations, stream cancellations, epoch rollovers) should make the action permissionless and reward the submitter from a vault. Fits.

## Privacy-specific constructions

- **Stealth addresses.** Built in: `(npk, vpk)` plus a random identifier is a stealth address per payment.
- **View keys for auditors.** Share the viewing seed `(d, z)` alone: the auditor sees every note and can neither advance nor spend. Fits, at the key-management layer.
- **Deposit keys for payers.** Share `nsk` plus the viewing seed, keep `ask`: the holder can see the account and credit it repeatedly (as an unauthorized recipient) but never spend. A payroll processor paying into one account instead of a slot per salary; a merchant terminal that checks and tops up a customer balance. Fits at the protocol level; the wallet needs a small identity for it. See [Deposit keys](../foundations/private-accounts.md#deposit-keys-sharing-nsk-and-vsk-without-ask).
- **Private program logic.** Shadow programs: the bytecode is never deployed and never claimed. Fits, private-state-only.
- **Selective program disclosure.** Undisclosed programs: prove "some immutable program" ran. Fits when there are no public effects.
- **Mixing service.** Unnecessary: private transfers already mix. A "mixer" that improves the anonymity set is just more private transfers.
- **Private DAO with hidden treasury and hidden votes.** Strained: hidden treasury fits (group PDA); hidden votes with a live tally does not (single-writer); voting Design B with the DAO itself as tallier fits.

## Things that do not fit, collected

| Idea | Why not | Nearest substitute |
|---|---|---|
| Read someone else's private state | notes are decryptable only by the viewing key | the owner's transaction attests a fact |
| Pay into an existing private account of someone else | updates need `nsk` | initialize a fresh slot under their key, or hold a deposit key they gave you |
| Many concurrent writers to private state | one nullifier per commitment | public state with commutative effects |
| Hidden live tally / hidden aggregate | same | trusted tallier, or sequential group updates |
| Randomness | no beacon | commit-reveal with bonds |
| Scheduled execution | no timers | permissionless keeper actions |
| Reading public state inside a proof | `PublicShardUnavailable` | guards evaluated at settlement |
| Encrypted effects on public shards | settlement applies effects in the clear | keep the shard private, or accept visibility |
| Private deployment | loader is public-only | shadow programs (no deployment at all) |
| Program that hides its identity and touches public state | effects name the program | split: shadow logic + a disclosed public-side program |
| More than seven private accounts hidden per tx | wallet padding bound | batch across transactions |
| Notes larger than 8 KiB that are uniform | protocol pad cap | keep private shards small |
| Fee-paying private transactions | not implemented (exempt) | wait; design for a future payer link |
| Event emission from private execution | events dropped | write a shard |
| Cross-zone private messages | inbox is public | none today |
