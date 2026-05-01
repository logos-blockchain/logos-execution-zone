# Protocol Specification: LP-0016 Anonymous Forum

This document outlines the cryptographic primitives, trust models, and threat mitigation strategies employed in the Logos Anonymous Forum protocol.

## 1. Unlinkability Argument

The core guarantee of this protocol is absolute unlinkability between an author's posts, ensuring a true marketplace of ideas devoid of reputational bias. 

### 1.1. Mathematical Definition of Unlinkability
Let $\mathcal{U}$ be the set of all registered, non-revoked members in the forum instance. Each member $u \in \mathcal{U}$ possesses a unique, highly entropic Nullifier Secret Key ($NSK$).

For any given post $P$, the author generates a moderation identifier, defined as the `tracing_tag` ($T$). The tag is deterministically derived using a collision-resistant cryptographic hash function (SHA-256):

$$T = \text{SHA256}(NSK \parallel H(M) \parallel S)$$

Where:
* $NSK$: The author's 32-byte secret key.
* $H(M)$: The 32-byte SHA-256 hash of the post message payload.
* $S$: A 32-byte cryptographically secure random salt generated ephemerally per post.

**Theorem 1 (Post Unlinkability):** *Given two distinct valid posts $P_1$ and $P_2$, generating tags $T_1$ and $T_2$, no probabilistic polynomial-time (PPT) adversary $\mathcal{A}$ (including the moderation subset) can determine if $P_1$ and $P_2$ share the same $NSK$ with a probability significantly greater than random guessing.*

**Proof Sketch:**
Because SHA-256 acts as a pseudo-random function (PRF) when keyed with a high-entropy secret ($NSK$), the output $T$ is computationally indistinguishable from a random 32-byte string to any party lacking knowledge of the $NSK$. Even if $\mathcal{A}$ knows $H(M_1)$ and $H(M_2)$, the presence of a unique salt $S$ ensures that $T_1$ and $T_2$ exhibit no mathematical correlation. The only entity capable of computing $T$ or linking $T_1$ to $T_2$ is the holder of the $NSK$.

### 1.2. The Anonymity Set
The anonymity set size at any given time $t$ is exactly the number of unrevoked commitments present in the Membership Registry smart contract. 

Let $\mathcal{R}$ be the Sparse Merkle Tree (SMT) maintaining all historical commitments, and $\mathcal{B}$ be the set of revoked commitments (blacklist). The anonymity set $A$ is:
$$|A| = |\mathcal{R}_{leaves}| - |\mathcal{B}|$$

When a user posts, they construct a Zero-Knowledge Proof (via RISC Zero ZKVM) that asserts:
1.  **Inclusion:** $\exists C \in \mathcal{R}$ such that $C$ is derived from $NSK$.
2.  **Validity:** $C \notin \mathcal{B}$.
3.  **Integrity:** $T$ was correctly computed using the exact $NSK$ tied to $C$.

The ZK proof ($\pi$) reveals only the public inputs (the SMT Root, the blacklist $\mathcal{B}$, $H(M)$, $S$, and $T$). It leaks zero bits of information regarding the specific Merkle path or the $NSK$, thus perfectly preserving the anonymity set size for every individual post.

## 2. Retroactive Deanonymization Property

While Section 1 guarantees absolute unlinkability for actors operating within the bounds of the forum's rules, the protocol introduces a strict, cryptographically enforced penalty for malicious behavior: **Retroactive Deanonymization**. This ensures that the system is not a safe haven for persistent toxic actors.

### 2.1. The Deanonymization Trigger (NSK Exposure)
The anonymity of a user is strictly bound to the secrecy of their Nullifier Secret Key ($NSK$). The moderation subsystem utilizes a Two-Tier Shamir's Secret Sharing scheme. When a member accumulates $K$ valid moderation strikes, the `SlashAggregator` collects enough shares to satisfy the threshold. 

Through Lagrange interpolation, the aggregator reconstructs the underlying polynomial $f(x)$ at the y-intercept $f(0)$, which perfectly outputs the member's $NSK$. This $NSK$ is then submitted on-chain via the `MembershipInstruction::Slash` transaction. Once executed and finalized in a block, the $NSK$ transitions from a local private secret to globally accessible public knowledge.

### 2.2. Mathematical Verification of Historical Posts
Upon the public exposure of an $NSK$, the anonymity set for that specific user immediately collapses to zero. Any third-party observer, indexer, or forum participant can retroactively evaluate the entire public ledger to identify every single post previously authored by the slashed member.

For every historical post $P_i$ in the forum, the observer extracts the public parameters from the ZK Receipt Journal: the message hash $H(M_i)$, the ephemeral salt $S_i$, and the published tracing tag $T_i$. 
The observer then independently computes the expected tag:

$$T'_{i} = \text{SHA256}(NSK_{slashed} \parallel H(M_i) \parallel S_i)$$

**Theorem 2 (Deterministic Linkability):** *If the computed $T'_{i}$ perfectly matches the published $T_i$ ($T'_{i} == T_i$), then post $P_i$ is definitively and incontrovertibly proven to be authored by the owner of $NSK_{slashed}$. Due to the collision resistance of the SHA-256 hash function, the probability of a false positive (a post from a different user serendipitously producing the same $T$) is cryptographically negligible ($\approx 2^{-256}$).*

### 2.3. Game-Theoretic Deterrence
This mathematical property enforces a severe game-theoretic deterrent against Sybil attacks and persistent trolling. Malicious actors are mathematically guaranteed that reaching the $K$-strike threshold does not merely result in:
1.  **Financial Loss:** The immediate forfeiture of their staked tokens (1000 tokens minimum).
2.  **Future Exclusion:** The insertion of their $Commitment$ into the on-chain blacklist ($\mathcal{B}$), preventing any future ZK proofs from validating.

More importantly, it carries the ultimate social penalty: **Complete Historical Exposure**. The permanent and undeniable cryptographic linking of all their past activities. Because the enforcement is trustless and executes purely through mathematical reconstruction, malicious actors cannot bribe or socially engineer the smart contract to halt the deanonymization process once $K$ strikes are accumulated.

## 3. Moderator Trust Assumptions

The Logos Anonymous Forum fundamentally rejects the concept of a centralized, omnipotent administrator. To mitigate the risk of rogue moderation and unilateral censorship, the protocol distributes the revocation power across a decentralized committee utilizing a Two-Tier Shamir's Secret Sharing (SSS) architecture.

### 3.1. The N-of-M Threshold Security Model
The moderation committee is defined as a predefined set of $M$ independent cryptographic keypairs (nodes/moderators). To successfully process a strike against a specific post, a minimum threshold of $N$ moderators must independently evaluate the payload, agree that a rule violation occurred, and contribute their decrypted share.

**Safety Assumption:** The protocol guarantees absolute protection against unauthorized deanonymization as long as the number of colluding, malicious moderators ($M_{corrupt}$) is strictly less than the threshold $N$:
$$M_{corrupt} \le N - 1$$

Due to the information-theoretic security properties of Shamir's Secret Sharing over a finite field $GF(p)$, any adversarial coalition holding $N-1$ or fewer shares possesses exactly zero bits of information regarding the underlying secret. Attempting to execute a Lagrange interpolation with an incomplete share set yields a uniformly random point in the field, rendering the true Nullifier Secret Key ($NSK$) mathematically indistinguishable from noise.

### 3.2. Two-Tier Collusion Resistance
The trust model extends beyond a simple threshold, requiring adversaries to breach a two-tier polynomial system to expose a user:
1.  **Tier 1 (Post-Level Validation):** At least $N$ moderators must collude to reconstruct a single valid strike ($S_{post}$) tied to a specific `tracing_tag`.
2.  **Tier 2 (Global-Level Accumulation):** The adversary must successfully execute the Tier 1 breach across $K$ distinct posts authored by the exact same user to accumulate the $K$ points required to reconstruct the ultimate $NSK$.

This rigorous two-tier structure ensures that even if $N$ moderators become momentarily corrupt, they cannot retroactively fabricate strikes or arbitrarily expose an innocent user. They must actively intercept, target, and successfully collude on $K$ distinct, mathematically verified interactions from that specific user.

### 3.3. Liveness vs. Safety Trade-offs
In distributed systems design, the protocol strictly prioritizes **Safety over Liveness**. 

While the safety of the user's identity relies on maintaining $\le N - 1$ corrupt moderators, the **liveness** of the moderation system (the ability to successfully ban a toxic actor) requires at least $N$ honest and operational moderators at any given time. 

If a network partition occurs or moderators go offline such that $M_{honest} < N$, the system gracefully degrades. It will temporarily fail to deanonymize the offender (loss of liveness, allowing the spam to persist momentarily), but it will never default to compromising the cryptographic anonymity of an innocent user (preservation of safety).

## 4. Threat Model and Mitigation Strategies

A robust cryptographic protocol must anticipate and neutralize adversarial actions from both external attackers and internal participants. This section outlines the primary attack vectors and the corresponding mitigation strategies embedded within the Logos Anonymous Forum architecture.

### 4.1. Sybil Attacks and Financial Exhaustion
**Threat:** An adversary attempts to overwhelm the forum by creating thousands of fake identities (Sybil nodes) to post spam, manipulate sentiment, or exhaust the moderation committee's resources, effectively bypassing the $K$-strike limitation by constantly rotating identities.

**Mitigation:** The protocol enforces an economic barrier to entry. Every $Commitment$ registered in the `MembershipRegistry` requires a minimum locked stake of 1,000 tokens (`MembershipInstruction::Register`). 
Because the $NSK$ is irrecoverably exposed and the stake is fully confiscated upon a successful slash (`MembershipInstruction::Slash`), a Sybil attack becomes prohibitively expensive. The attacker faces a linear financial penalty $C = S \times I_{slashed}$ (where $S$ is the stake per account and $I$ is the number of burned identities), neutralizing the economic viability of infinite identity generation.

### 4.2. ZK Proof Forgery and State Manipulation
**Threat:** A revoked user (blacklisted) or a non-member attempts to bypass the `VerifyPost` instruction by forging a RISC Zero ZK receipt, or by manipulating the Sparse Merkle Tree (SMT) path to prove membership without a valid $NSK$.

**Mitigation:** 1.  **Cryptographic Soundness:** The system relies on the computational soundness of the RISC Zero ZKVM. Forging a receipt without executing the actual ELF binary and producing a valid STARK proof implies breaking the underlying cryptographic assumptions of the RISC-V STARK prover, which is considered computationally infeasible.
2.  **On-Chain Root Verification:** The smart contract strictly verifies that the `registry_root` embedded within the ZK Journal perfectly matches the authoritative Merkle root stored in the L1 state.
3.  **In-Circuit Blacklist Evaluation:** The ZK circuit natively cross-references the derived $Commitment$ bytes against the array of `revoked_commitments` provided as public inputs. If the commitment exists in the blacklist, the circuit panics, preventing the generation of a valid receipt.

### 4.3. Replay Attacks and MEV / Front-Running
**Threat:** An adversary observes a valid `VerifyPost` transaction containing a ZK receipt in the mempool. They extract the receipt and replay it to authorize a different, malicious payload under the victim's anonymity shield. Alternatively, a malicious actor intercepts a `Slash` transaction to front-run the confiscation.

**Mitigation:**
1.  **Payload Binding:** The tracing tag $T = \text{SHA256}(NSK \parallel H(M) \parallel S)$ cryptographically binds the ZK proof to the specific message payload $H(M)$. If an adversary attempts to attach the intercepted receipt to a different message $M'$, the smart contract or the off-chain indexer will detect a mismatch between the provided payload and the $H(M)$ verified inside the ZK Journal, immediately rejecting the post.
2.  **Slash Idempotency:** The `Slash` instruction requires the raw $NSK$. If an MEV bot front-runs the transaction, the $NSK$ is still exposed, the commitment is added to the blacklist, and the protocol's primary goal (deanonymization and banning) is successfully achieved regardless of who initiated the final execution block.

### 4.4. Rogue Aggregation and False Strikes
**Threat:** The `SlashAggregator` acts maliciously by fabricating strikes or attempting to reconstruct an $NSK$ prematurely without gathering legitimate shares from $N$ moderators.

**Mitigation:** The `SlashAggregator` is an off-chain coordinator with **zero cryptographic authority**. 
* It cannot fabricate a strike because each share is encrypted and cryptographically bound to the moderator's Schnorr Signature.
* It cannot prematurely reconstruct the $NSK$ because Lagrange interpolation over a finite field mathematically requires at least $N$ points. Attempting to guess the polynomial with $N-1$ shares provides no probabilistic advantage.
* Furthermore, any observer or the smart contract can independently verify the legitimacy of the exposed $NSK$ by deriving the corresponding $Commitment$ and checking its existence in the Merkle Tree before executing the stake confiscation.