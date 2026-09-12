use kameo::Reply;
use logos_blockchain_codec::{BinaryDecodeExt as _, BinaryEncode as _};
use logos_blockchain_core::{
    mantle::{
        SignedMantleTx,
        ops::{
            OpProof,
            channel::{Ed25519PublicKey, MsgId},
        },
        transactions::{mantle_tx::RawMantleTx, states::Unverified},
    },
    proofs::channel_multi_sig_proof::IndexedSignature,
};

/// Tags the two message shapes on the wire. A draft is a whole
/// transaction; a signature is worthless without the one it was signed over,
/// so it carries that transaction's hash.
const DRAFT: u8 = 0;
const SIGNATURE: u8 = 1;

/// The channel config this node wants installed next.
///
/// Every accredited node derives the same target from the same finalized
/// state, which is what lets a peer judge someone else's draft without
/// trusting it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigTarget {
    /// The committee to install, in the order the op will carry it.
    pub keys: Vec<Ed25519PublicKey>,
    /// The config tip the op chains on. A draft dies when this moves.
    pub parent: MsgId,
    pub posting_timeframe: u32,
    pub posting_timeout: u32,
    /// Signatures the *next* config will have to carry, not this one.
    pub configuration_threshold: u16,
    pub transfer_threshold: u16,
}

/// What this node last saw of the live channel, plus the committee it should
/// have. Recomputed every turn, so a stale view is corrected rather than kept.
#[derive(Clone, Debug)]
pub struct ChannelView {
    /// Live accredited keys in index order; a signature names its index here.
    pub live_keys: Vec<Ed25519PublicKey>,
    /// Signatures the live channel demands of the next config op.
    pub required_signatures: u16,
    /// The config to install, or `None` when live already matches.
    pub target: Option<ConfigTarget>,
}

/// Asks what this turn owes the channel config. Only the turn holder proposes,
/// so only the turn holder sends this.
pub struct Propose;

/// What this turn owes the channel config, in answer to [`Propose`].
#[derive(Reply)]
pub enum Action {
    /// Nothing to do, or waiting on peers.
    Idle,
    /// No draft covers the target yet. Fund one and hand it back as
    /// [`FundedTx`]; funding needs a node round trip the actor cannot make.
    Build(Box<ConfigTarget>),
    /// Enough signatures are in. Submit this.
    Submit(Box<SignedMantleTx<Unverified>>),
}

/// A funded draft built for the target the actor asked to build, already
/// carrying this node's own signature.
pub struct FundedTx {
    pub target: Box<ConfigTarget>,
    pub tx: Box<RawMantleTx>,
    /// The fee transfer's proof, kept until the draft is assembled.
    pub transfer_proof: Option<OpProof>,
}

/// A funded config transaction on the wire, for whoever receives it to
/// check and sign.
#[derive(Clone, Debug)]
pub struct Draft {
    pub tx: Box<RawMantleTx>,
}

/// One accredited key's signature over a draft's transaction hash, carrying
/// the index that names the key in the live list.
#[derive(Clone, Debug)]
pub struct Signature {
    /// The draft signed. Signatures are worthless against any other.
    pub tx_hash: [u8; 32],
    pub signature: IndexedSignature,
}

/// Where this node publishes its own drafts and signatures; unset until
/// gossip is up, or when it is off.
pub struct SetPublisher(pub tokio::sync::mpsc::Sender<Wire>);

/// The two message shapes the channel-config topic carries, either way.
#[derive(Clone, Debug)]
pub enum Wire {
    Draft(Draft),
    Signature(Signature),
}

impl Wire {
    /// Encodes for gossip. The payload types are Bedrock's own, so they use
    /// Bedrock's codec rather than the borsh the zone's transactions use.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (tag, payload): (u8, Vec<u8>) = match self {
            Self::Draft(draft) => (DRAFT, draft.tx.encode().into_vec()),
            Self::Signature(signature) => {
                let mut bytes = signature.tx_hash.to_vec();
                bytes.extend_from_slice(&signature.signature.encode());
                (SIGNATURE, bytes)
            }
        };
        let mut bytes = Vec::with_capacity(payload.len().saturating_add(1));
        bytes.push(tag);
        bytes.extend_from_slice(&payload);

        bytes
    }

    /// Decodes a gossiped message. `None` for anything this build does not
    /// recognise, which a peer running a later one may well send.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (tag, payload) = bytes.split_first()?;
        match *tag {
            DRAFT => Some(Self::Draft(Draft {
                tx: Box::new(RawMantleTx::decode_all(payload).ok()?),
            })),
            SIGNATURE => {
                let (tx_hash, rest) = payload.split_at_checked(32)?;

                Some(Self::Signature(Signature {
                    tx_hash: tx_hash.try_into().ok()?,
                    signature: IndexedSignature::decode_all(rest).ok()?,
                }))
            }
            _ => None,
        }
    }
}
