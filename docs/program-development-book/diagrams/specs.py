"""Content of every execution diagram. One dict per diagram; see gen.py for the layout.

Keep chips to a few words (the generator refuses more than 24 characters) and at most three
per band. Explanations belong in the chapter text, not in the diagram.
"""

NOTES = "only unlinkable notes"

MULTISIG = [
    {
        "id": "multisig-all-public",
        "title": "Multisig: all public",
        "subtitle": "Public members, public vault, public recipient.",
        "columns": [
            {"head": "Propose", "who": "Alice", "tx": "public",
             "chain": ["Alice signs", "pay Dave 100"]},
            {"head": "Approve", "who": "Alice, Bob", "tx": "public",
             "chain": ["Alice, Bob sign", "2 approvals"]},
            {"head": "Execute", "who": "anyone", "tx": "public",
             "chain": ["vault -100", "Dave +100"]},
        ],
    },
    {
        "id": "multisig-anonymous-member",
        "title": "Multisig: anonymous member",
        "subtitle": "Carol is a private member: the config holds only a hash of her secret.",
        "columns": [
            {"head": "Propose", "who": "Alice", "tx": "public",
             "chain": ["Alice signs", "pay Dave 100"]},
            {"head": "Approve", "who": "Alice", "tx": "public",
             "chain": ["Alice signs", "approval: slot 0"]},
            {"head": "Approve", "who": "Carol", "tx": "private",
             "hidden": ["who Carol is", "her secret"],
             "chain": ["approval: slot 2"]},
            {"head": "Execute", "who": "anyone", "tx": "public",
             "chain": ["vault -100", "Dave +100"]},
        ],
    },
    {
        "id": "multisig-hidden-treasury",
        "title": "Multisig: hidden treasury",
        "subtitle": "Public board, private vault (group key), private recipient.",
        "columns": [
            {"head": "Propose", "who": "Alice", "tx": "public",
             "hidden": ["pay Dave 100"],
             "chain": ["Alice signs", "proposal: a hash"]},
            {"head": "Approve", "who": "Alice, Bob", "tx": "public",
             "chain": ["2 approvals"]},
            {"head": "Execute", "who": "Bob", "tx": "private",
             "hidden": ["amount", "Dave", "vault balance"],
             "chain": ["proposal executed"]},
        ],
    },
    {
        "id": "multisig-all-private",
        "title": "Multisig: all private",
        "subtitle": "Group-held board and vault; the multisig runs undisclosed. Members take turns.",
        "columns": [
            {"head": "Propose", "who": "Alice", "tx": "private",
             "hidden": ["pay Dave 100"], "chain": [NOTES]},
            {"head": "Approve", "who": "Bob", "tx": "private",
             "hidden": ["Bob approves"], "chain": [NOTES]},
            {"head": "Execute", "who": "to a private Dave", "tx": "private",
             "hidden": ["which vault paid", "Dave", "amount"], "chain": [NOTES]},
            {"head": "Execute", "who": "or: to a public Dave", "tx": "private",
             "hidden": ["which vault paid"], "chain": ["Dave +100"]},
        ],
    },
]

DONATIONS = [
    {
        "id": "donations-three-placements",
        "title": "Donation: three placements",
        "subtitle": "Three alternatives, not a sequence.",
        "columns": [
            {"head": "Private donor", "who": "to the charity's key", "tx": "private",
             "hidden": ["donor", "amount"], "chain": [NOTES]},
            {"head": "Public donor", "who": "to the charity's key", "tx": "private",
             "hidden": ["recipient"], "chain": ["donor signs", "donor -amount"]},
            {"head": "Private donor", "who": "to a public account", "tx": "private",
             "hidden": ["donor"], "chain": ["charity +amount"]},
        ],
    },
    {
        "id": "donations-campaign",
        "title": "Donation: matched campaign",
        "subtitle": "Public campaign and match vault, private donor.",
        "columns": [
            {"head": "Create", "who": "organizer", "tx": "public",
             "chain": ["campaign created"]},
            {"head": "Fund match", "who": "sponsor", "tx": "public",
             "chain": ["match vault +1000"]},
            {"head": "Donate", "who": "donor", "tx": "private",
             "hidden": ["donor", "donor's receipt"],
             "chain": ["raised +50, matched +50"]},
        ],
    },
]

AMM = [
    {
        "id": "amm-prepared-offer",
        "title": "AMM: a prepared private offer",
        "subtitle": "Offer: pay 100 A, receive exactly 75 B. Proven once, settled later.",
        "columns": [
            {"head": "Prove", "who": "trader", "tx": "offchain",
             "hidden": ["the offer"]},
            {"head": "Settle", "who": "price still fine", "tx": "private",
             "hidden": ["trader"], "chain": ["pool: 100 A in, 75 B out"]},
            {"head": "Settle", "who": "price moved", "tx": "refused",
             "hidden": ["note still unspent"], "chain": ["refused, no change"]},
        ],
    },
]

STREAMS = [
    {
        "id": "streams-public-stream-private-recipient",
        "title": "Stream: private recipient",
        "subtitle": "Public schedule and vault; the recipient is gated by a secret.",
        "columns": [
            {"head": "Open", "who": "payer", "tx": "public",
             "chain": ["vault +1200", "12-month schedule"]},
            {"head": "Withdraw", "who": "recipient", "tx": "private",
             "hidden": ["recipient"], "chain": ["vault -100"]},
            {"head": "Cancel", "who": "payer", "tx": "public",
             "chain": ["rest back to payer"]},
        ],
    },
    {
        "id": "streams-private-stream",
        "title": "Stream: fully private",
        "subtitle": "Record and funds on one private PDA under the recipient's key.",
        "columns": [
            {"head": "Open", "who": "payer", "tx": "private",
             "hidden": ["payer", "amount"], "chain": ["stream program named"]},
            {"head": "Withdraw", "who": "recipient", "tx": "private",
             "hidden": ["recipient", "amount"], "chain": ["clock check"]},
        ],
    },
]

VOTING = [
    {
        "id": "voting-anonymous-voters",
        "title": "Vote: anonymous voters",
        "subtitle": "Voters are a Merkle root of secret hashes; the tally is public.",
        "columns": [
            {"head": "Create", "who": "organizer", "tx": "public",
             "chain": ["voter list (a root)"]},
            {"head": "Vote", "who": "Carol", "tx": "private",
             "hidden": ["who voted"], "chain": ["option 2 +1"]},
            {"head": "Vote again", "who": "Carol", "tx": "refused",
             "chain": ["refused"]},
        ],
    },
    {
        "id": "voting-secret-ballots",
        "title": "Vote: secret ballots",
        "subtitle": "Vote tokens sent privately to a tallier, who publishes the count.",
        "columns": [
            {"head": "Vote", "who": "each voter", "tx": "private",
             "hidden": ["who", "which option"], "chain": ["token program named"]},
            {"head": "Count", "who": "tallier", "tx": "private",
             "hidden": ["who voted what"], "chain": ["option 2: 5 votes"]},
        ],
    },
]

RLN = [
    {
        "id": "rln-lifecycle",
        "title": "RLN: registry on chain, rate limit off chain",
        "subtitle": "The chain only knows who is a member. Peers check the proofs.",
        "columns": [
            {"head": "Register", "who": "a member", "tx": "public",
             "chain": ["member signs", "treasury + fee", "leaf added, new root"]},
            {"head": "Send messages", "who": "member to network", "tx": "offchain",
             "hidden": ["proof: I am in the tree", "one point of my secret"]},
            {"head": "Overspend", "who": "member to network", "tx": "offchain",
             "hidden": ["two points, one slot", "secret now computable"]},
            {"head": "Slash", "who": "anyone", "tx": "public",
             "chain": ["the secret", "leaf removed, new root"]},
        ],
    },
    {
        "id": "rln-private-registration",
        "title": "RLN: registering from a private account",
        "subtitle": "The same instruction. Nobody learns who became a member.",
        "columns": [
            {"head": "Register", "who": "a member", "tx": "private",
             "hidden": ["who paid"],
             "chain": ["treasury + fee", "leaf added, new root"]},
            {"head": "Send messages", "who": "member to network", "tx": "offchain",
             "hidden": ["proof: I am in the tree", "one point of my secret"]},
            {"head": "Slash", "who": "anyone", "tx": "public",
             "chain": ["the secret", "leaf removed, new root"]},
        ],
    },
]

ESCROW = [
    {
        "id": "escrow-htlc-private-claim",
        "title": "Hash lock: private claim",
        "subtitle": "The preimage never appears on chain.",
        "columns": [
            {"head": "Lock", "who": "buyer", "tx": "public",
             "chain": ["vault +100", "hash H"]},
            {"head": "Claim", "who": "seller", "tx": "private",
             "hidden": ["seller", "preimage"], "chain": ["vault -100"]},
        ],
    },
    {
        "id": "escrow-pairwise-swap",
        "title": "Two-party private swap",
        "subtitle": "Both legs held on one private PDA under a shared pairwise key.",
        "columns": [
            {"head": "Offer", "who": "Alice", "tx": "private",
             "hidden": ["Alice's leg"], "chain": ["swap program named"]},
            {"head": "Accept", "who": "Bob", "tx": "private",
             "hidden": ["Bob's leg"], "chain": ["swap program named"]},
        ],
    },
]

TOKENS = [
    {
        "id": "tokens-placements",
        "title": "Token transfer: four placements",
        "subtitle": "Four alternatives of one Transfer.",
        "columns": [
            {"head": "Public to public", "who": "", "tx": "public",
             "chain": ["sender signs", "amount"]},
            {"head": "Private to private", "who": "", "tx": "private",
             "hidden": ["both sides", "amount"], "chain": ["token program named"]},
            {"head": "Private to public", "who": "", "tx": "private",
             "hidden": ["sender"], "chain": ["recipient +amount", "token program named"]},
            {"head": "Public to private", "who": "", "tx": "private",
             "hidden": ["recipient"], "chain": ["sender signs", "sender -amount"]},
        ],
    },
]

ATTESTATIONS = [
    {
        "id": "attestations-ticket",
        "title": "Ticket at the door",
        "subtitle": "The ticket stays private; the door only counts admissions.",
        "columns": [
            {"head": "Buy", "who": "holder", "tx": "private",
             "hidden": ["which ticket"], "chain": ["token program named"]},
            {"head": "Admit", "who": "holder", "tx": "private",
             "hidden": ["which ticket"], "chain": ["admissions +1"]},
            {"head": "Admit again", "who": "same ticket", "tx": "refused",
             "chain": ["refused"]},
        ],
    },
]

LEZORK = [
    {
        "id": "lezork-moves",
        "title": "LeZork: a private player",
        "subtitle": "Rooms are public; the player's position and inventory are private.",
        "columns": [
            {"head": "Go north", "who": "player", "tx": "private",
             "hidden": ["who"], "chain": ["someone: X to Y"]},
            {"head": "Take lamp", "who": "player", "tx": "private",
             "hidden": ["who"], "chain": ["lamp gone from Y"]},
            {"head": "Solve riddle", "who": "player", "tx": "private",
             "hidden": ["who", "the answer"], "chain": ["door Z opened"]},
            {"head": "Go (blind)", "who": "player", "tx": "private",
             "hidden": ["who", "where"], "chain": ["a move happened"]},
        ],
    },
]

CHANNELS = [
    {
        "id": "channels-one-way",
        "title": "A payment channel: private recipient",
        "subtitle": "The recipient redeems for themselves, into a fresh private slot.",
        "columns": [
            {"head": "Open", "who": "payer", "tx": "public",
             "chain": ["vault +100", "recipient: a gate"]},
            {"head": "Pay, many times", "who": "payer to recipient", "tx": "offchain",
             "hidden": ["voucher: total 1", "voucher: total 2", "... total 64"]},
            {"head": "Redeem", "who": "recipient", "tx": "private",
             "hidden": ["recipient"], "chain": ["voucher: total 64", "vault -64"]},
            {"head": "Close", "who": "payer, after expiry", "tx": "public",
             "chain": ["rest back to payer"]},
        ],
    },
]

CHANNELS += [
    {
        "id": "channels-all-public",
        "title": "A payment channel: all public",
        "subtitle": "Public payer, public recipient. Anyone holding a voucher can redeem.",
        "columns": [
            {"head": "Open", "who": "payer", "tx": "public",
             "chain": ["payer signs", "vault +100"]},
            {"head": "Pay, many times", "who": "payer to recipient", "tx": "offchain",
             "hidden": ["voucher: total 1", "voucher: total 2", "... total 64"]},
            {"head": "Redeem", "who": "anyone with a voucher", "tx": "public",
             "chain": ["voucher: total 64", "recipient +64"]},
            {"head": "Close", "who": "payer, after expiry", "tx": "public",
             "chain": ["rest back to payer"]},
        ],
    },
    {
        "id": "channels-private-payer",
        "title": "A payment channel: private payer",
        "subtitle": "The vault is funded from a private balance. The refund goes to a fresh slot.",
        "columns": [
            {"head": "Open", "who": "payer", "tx": "private",
             "hidden": ["payer"], "chain": ["vault +100", "refund: a gate"]},
            {"head": "Pay, many times", "who": "payer to recipient", "tx": "offchain",
             "hidden": ["voucher: total 1", "... total 64"]},
            {"head": "Redeem", "who": "anyone with a voucher", "tx": "public",
             "chain": ["voucher: total 64", "recipient +64"]},
            {"head": "Close", "who": "payer, after expiry", "tx": "private",
             "hidden": ["payer"], "chain": ["vault -36"]},
        ],
    },
]

BATTLESHIP = [
    {
        "id": "battleship-shot",
        "title": "Battleship: one shot",
        "subtitle": "The answer is a guard on the defender's private board, inside the proof.",
        "columns": [
            {"head": "Join", "who": "each player", "tx": "private",
             "hidden": ["the fleet"], "chain": ["a board took a seat"]},
            {"head": "Fire", "who": "shooter", "tx": "private",
             "hidden": ["shooter's fleet"], "chain": ["shot at C4"]},
            {"head": "Answer", "who": "defender", "tx": "private",
             "hidden": ["defender's fleet"], "chain": ["C4: hit"]},
        ],
    },
]

RADIO = [
    {
        "id": "radio-messages",
        "title": "Deep Space Radio",
        "subtitle": "Ships are private. A radio message is a fresh private slot. Docking is the only reveal.",
        "columns": [
            {"head": "Move", "who": "a ship", "tx": "private",
             "hidden": ["from where", "to where"], "chain": [NOTES]},
            {"head": "Radio", "who": "ship to ship", "tx": "private",
             "hidden": ["sender", "receiver", "text and cargo"], "chain": [NOTES]},
            {"head": "Take", "who": "the other ship", "tx": "private",
             "hidden": ["cargo taken aboard"], "chain": [NOTES]},
            {"head": "Dock", "who": "a ship", "tx": "private",
             "hidden": ["which ship", "its cargo"],
             "chain": ["a ship docked", "at station 4"]},
        ],
    },
]

DIAGRAMS = (MULTISIG + DONATIONS + AMM + STREAMS + CHANNELS + VOTING + RLN + ESCROW + TOKENS
            + ATTESTATIONS + LEZORK + BATTLESHIP + RADIO)
