"""Content of every execution diagram. One dict per diagram; see gen.py for the layout.

Keep chips to a few words and at most three per band. Explanations belong in the chapter
text, not in the diagram.
"""

NOTES = "only unlinkable notes"

DONATIONS = [
    {
        "id": "donations-mailbox",
        "title": "A donation to a private cause",
        "subtitle": "The credit waits on chain until the cause collects it.",
        "columns": [
            {"head": "Donate", "who": "a public donor", "tx": "public",
             "chain": ["donor -10", "credit 10, stored", "to: an address"]},
            {"head": "Or donate", "who": "a private donor", "tx": "private",
             "hidden": ["donor", "amount", "to whom"],
             "chain": ["a sealed message"]},
            {"head": "Collect", "who": "the cause, later", "tx": "private",
             "hidden": ["which credit", "new balance"], "chain": [NOTES]},
        ],
    },
]

REQUESTS = [
    {
        "id": "requests-accept",
        "title": "A payment request: private requester",
        "subtitle": "Collecting with the spending key is the acceptance.",
        "columns": [
            {"head": "Request", "who": "Bob (private)", "tx": "private",
             "hidden": ["pay Bob 10", "to Alice"], "chain": ["a sealed message"]},
            {"head": "Read", "who": "Alice's wallet", "tx": "offchain",
             "hidden": ["Alice sees the request"]},
            {"head": "Accept", "who": "Alice, with her key", "tx": "private",
             "hidden": ["Alice -10", "credit to Bob"], "chain": ["a sealed message"]},
            {"head": "Or decline", "who": "Alice", "tx": "offchain",
             "hidden": ["she does nothing"]},
        ],
    },
]

MULTISIG = [
    {
        "id": "multisig-all-public",
        "title": "Multisig: public vault, public members",
        "subtitle": "Each approval is delivered to the vault at once.",
        "columns": [
            {"head": "Approve", "who": "Alice", "tx": "public",
             "chain": ["Alice signs", "pay Dave 100: 1 of 2"]},
            {"head": "Approve", "who": "Bob", "tx": "public",
             "chain": ["Bob signs", "2 of 2", "vault -100, Dave +100"]},
        ],
    },
    {
        "id": "multisig-hidden-members",
        "title": "Multisig: public vault, hidden member",
        "subtitle": "Carol's seat approves from a blinded address.",
        "columns": [
            {"head": "Approve", "who": "Alice", "tx": "public",
             "chain": ["Alice signs", "1 of 2"]},
            {"head": "Approve", "who": "Carol", "tx": "private",
             "hidden": ["who Carol is"],
             "chain": ["seat #3 approves", "2 of 2", "vault -100, Dave +100"]},
        ],
    },
    {
        "id": "multisig-hidden-vault",
        "title": "Multisig: hidden vault, hidden members",
        "subtitle": "Approvals are sealed messages. Any member collects them.",
        "columns": [
            {"head": "Approve", "who": "Alice", "tx": "private",
             "hidden": ["Alice approves"], "chain": ["a sealed message"]},
            {"head": "Approve", "who": "Bob", "tx": "private",
             "hidden": ["Bob approves"], "chain": ["a sealed message"]},
            {"head": "Collect 1", "who": "any member", "tx": "private",
             "hidden": ["1 of 2"], "chain": [NOTES]},
            {"head": "Collect 2", "who": "any member", "tx": "private",
             "hidden": ["2 of 2", "vault pays Dave"], "chain": ["a sealed message"]},
        ],
    },
]

STREAMS = [
    {
        "id": "streams-private-recipient",
        "title": "A stream: private recipient",
        "subtitle": "Anyone can release. The recipient collects when convenient.",
        "columns": [
            {"head": "Open", "who": "the payer", "tx": "public",
             "chain": ["stream funded", "rate, start", "to: an address"]},
            {"head": "Release", "who": "anyone", "tx": "public",
             "chain": ["stream -30", "credit 30, stored"]},
            {"head": "Collect", "who": "the recipient", "tx": "private",
             "hidden": ["which credit", "new balance"], "chain": [NOTES]},
        ],
    },
]

CHANNELS = [
    {
        "id": "channels-one-way",
        "title": "A payment channel: private payer and recipient",
        "subtitle": "The payer funds from a private account. The payout waits for the recipient.",
        "columns": [
            {"head": "Open", "who": "the payer", "tx": "private",
             "hidden": ["who the payer is"],
             "chain": ["channel funded: 100", "recipient: an address"]},
            {"head": "Pay, many times", "who": "payer to recipient", "tx": "offchain",
             "hidden": ["voucher: total 1", "voucher: total 2", "... total 64"]},
            {"head": "Redeem", "who": "anyone with a voucher", "tx": "public",
             "chain": ["voucher: total 64", "credit 64, stored"]},
            {"head": "Close", "who": "anyone, after expiry", "tx": "public",
             "chain": ["refund 36, stored"]},
        ],
    },
]

VOTING = [
    {
        "id": "voting-anonymous",
        "title": "An election: private voter",
        "subtitle": "The tally trusts a vote because its own program sent it.",
        "columns": [
            {"head": "Open", "who": "the organiser", "tx": "public",
             "chain": ["ballots, stored", "to: each voter"]},
            {"head": "Collect ballot", "who": "Dana", "tx": "private",
             "hidden": ["Dana has a ballot"], "chain": [NOTES]},
            {"head": "Vote", "who": "Dana", "tx": "private",
             "hidden": ["who voted", "ballot now used"],
             "chain": ["a ballot votes Yes", "tally: Yes +1"]},
        ],
    },
]

CREDENTIALS = [
    {
        "id": "credentials-show",
        "title": "Showing a badge: private holder",
        "subtitle": "The venue learns that a real badge was shown, not whose.",
        "columns": [
            {"head": "Issue", "who": "the issuer", "tx": "public",
             "chain": ["badge, stored", "to: an address"]},
            {"head": "Collect", "who": "the holder", "tx": "private",
             "hidden": ["holder has a badge"], "chain": [NOTES]},
            {"head": "Show", "who": "the holder", "tx": "private",
             "hidden": ["which badge", "who"],
             "chain": ["a badge from issuer X", "venue admits"]},
        ],
    },
]

AUCTION = [
    {
        "id": "auction-sealed-bid",
        "title": "A sealed-bid auction",
        "subtitle": "The bid stays in the bidder's private state until the reveal.",
        "columns": [
            {"head": "Bid", "who": "a bidder", "tx": "private",
             "hidden": ["who", "the amount"], "chain": ["a paddle joined"]},
            {"head": "Reveal", "who": "the bidder", "tx": "private",
             "hidden": ["who"], "chain": ["that paddle bid 70"]},
            {"head": "Settle", "who": "anyone", "tx": "public",
             "chain": ["highest: 70", "winner: a pseudonym"]},
        ],
    },
]

RADIO = [
    {
        "id": "radio-messages",
        "title": "Deep Space Radio",
        "subtitle": "Ships are private. Radio is a sealed message. Docking is the only reveal.",
        "columns": [
            {"head": "Move", "who": "a ship", "tx": "private",
             "hidden": ["from where", "to where"], "chain": [NOTES]},
            {"head": "Radio", "who": "ship to ship", "tx": "private",
             "hidden": ["sender", "receiver", "text and cargo"],
             "chain": ["a sealed message"]},
            {"head": "Receive", "who": "the other ship", "tx": "private",
             "hidden": ["cargo taken aboard"], "chain": [NOTES]},
            {"head": "Dock", "who": "a ship", "tx": "private",
             "hidden": ["which ship", "its cargo"],
             "chain": ["call sign K7 docked", "at station 4"]},
        ],
    },
]

BATTLESHIP = [
    {
        "id": "battleship-shot",
        "title": "Battleship: one shot",
        "subtitle": "The answer is computed from the hidden fleet, inside the proof.",
        "columns": [
            {"head": "Place", "who": "each player", "tx": "private",
             "hidden": ["the fleet"], "chain": [NOTES]},
            {"head": "Fire", "who": "the shooter", "tx": "private",
             "hidden": ["the shooter's fleet"], "chain": ["shot at C4"]},
            {"head": "Answer", "who": "the defender", "tx": "private",
             "hidden": ["the defender's fleet"], "chain": ["C4: hit"]},
        ],
    },
]


PUBLIC_FLOWS = [
    {
        "id": "channels-all-public",
        "title": "A payment channel: all public",
        "subtitle": "The same program with a public payer and a public recipient.",
        "columns": [
            {"head": "Open", "who": "the payer", "tx": "public",
             "chain": ["payer signs", "channel funded: 100"]},
            {"head": "Pay, many times", "who": "payer to recipient", "tx": "offchain",
             "hidden": ["voucher: total 1", "voucher: total 2", "... total 64"]},
            {"head": "Redeem", "who": "anyone with a voucher", "tx": "public",
             "chain": ["voucher: total 64", "recipient +64"]},
            {"head": "Close", "who": "anyone, after expiry", "tx": "public",
             "chain": ["payer +36"]},
        ],
    },
    {
        "id": "streams-all-public",
        "title": "A stream: all public",
        "subtitle": "The credit lands in the same transaction as the release.",
        "columns": [
            {"head": "Open", "who": "the payer", "tx": "public",
             "chain": ["payer signs", "stream funded", "rate, start"]},
            {"head": "Release", "who": "anyone", "tx": "public",
             "chain": ["stream -30", "recipient +30"]},
        ],
    },
    {
        "id": "tokens-four-transfers",
        "title": "One transfer, four placements",
        "subtitle": "The handler is the same in all four. Only the accounts differ.",
        "columns": [
            {"head": "Public to public", "who": "Alice to Bob", "tx": "public",
             "chain": ["Alice -5", "Bob +5"]},
            {"head": "Public to private", "who": "Alice to Bob", "tx": "public",
             "hidden": ["who Bob is"], "chain": ["Alice -5", "credit 5, stored"]},
            {"head": "Private to public", "who": "Alice to Bob", "tx": "private",
             "hidden": ["who Alice is"], "chain": ["Bob +5"]},
            {"head": "Private to private", "who": "Alice to Bob", "tx": "private",
             "hidden": ["Alice", "Bob", "the amount"], "chain": ["a sealed message"]},
        ],
    },
    {
        "id": "escrow-all-public",
        "title": "Escrow: all public",
        "subtitle": "Buyer and seller are ordinary public accounts.",
        "columns": [
            {"head": "Open", "who": "the buyer", "tx": "public",
             "chain": ["buyer signs", "deal funded: 50"]},
            {"head": "Release", "who": "the buyer", "tx": "public",
             "chain": ["buyer signs", "seller +50"]},
        ],
    },
    {
        "id": "escrow-private-parties",
        "title": "Escrow: private buyer and seller",
        "subtitle": "The deal holds only addresses. Each party speaks through a seat.",
        "columns": [
            {"head": "Open", "who": "the buyer", "tx": "private",
             "hidden": ["who the buyer is"],
             "chain": ["deal: three addresses", "deal funded: 50"]},
            {"head": "Release", "who": "the buyer", "tx": "private",
             "hidden": ["who the buyer is"],
             "chain": ["buyer's seat: release", "credit 50, stored"]},
            {"head": "Collect", "who": "the seller", "tx": "private",
             "hidden": ["who the seller is"], "chain": [NOTES]},
        ],
    },
    {
        "id": "requests-public-requester",
        "title": "A payment request: public requester",
        "subtitle": "The request is readable by everyone. The payer stays hidden.",
        "columns": [
            {"head": "Request", "who": "Bob (public)", "tx": "public",
             "chain": ["Bob signs", "request: pay Bob 10", "to: an address"]},
            {"head": "Read", "who": "Alice's wallet", "tx": "offchain",
             "hidden": ["Alice sees the request"]},
            {"head": "Accept", "who": "Alice, with her key", "tx": "private",
             "hidden": ["who Alice is"], "chain": ["Bob +10"]},
        ],
    },
    {
        "id": "voting-public-voter",
        "title": "An election: public voter",
        "subtitle": "The same program. A voter who uses a public account votes in the open.",
        "columns": [
            {"head": "Open", "who": "the organiser", "tx": "public",
             "chain": ["ballot delivered", "to: Dana"]},
            {"head": "Vote", "who": "Dana", "tx": "public",
             "chain": ["Dana signs", "Dana votes Yes", "tally: Yes +1"]},
        ],
    },
    {
        "id": "credentials-public-holder",
        "title": "Showing a badge: public holder",
        "subtitle": "The same program. The venue learns who is showing the badge.",
        "columns": [
            {"head": "Issue", "who": "the issuer", "tx": "public",
             "chain": ["badge delivered", "to: Hal"]},
            {"head": "Show", "who": "Hal", "tx": "public",
             "chain": ["Hal signs", "a badge from issuer X", "venue admits Hal"]},
        ],
    },
    {
        "id": "multisig-hidden-vault-public-members",
        "title": "Multisig: hidden vault, public members",
        "subtitle": "The weak combination: approvals are readable, the vault is not.",
        "columns": [
            {"head": "Approve", "who": "Alice", "tx": "public",
             "chain": ["Alice signs", "approval, stored", "to: the vault"]},
            {"head": "Approve", "who": "Bob", "tx": "public",
             "chain": ["Bob signs", "approval, stored", "to: the vault"]},
            {"head": "Collect both", "who": "any member, twice", "tx": "private",
             "hidden": ["2 of 2", "vault pays Dave"], "chain": ["a sealed message"]},
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
        "subtitle": "The same handler. Nobody learns who became a member.",
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

DIAGRAMS = (DONATIONS + REQUESTS + MULTISIG + STREAMS + CHANNELS + VOTING + CREDENTIALS
            + AUCTION + RADIO + BATTLESHIP + PUBLIC_FLOWS + RLN)
