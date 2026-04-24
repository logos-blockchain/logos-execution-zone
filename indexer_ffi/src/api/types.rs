pub type HashType = [u8; 32];
pub type MsgId = [u8; 32];
pub type BlockId = u64;
pub type Timestamp = u64;
pub type Signature = [u8; 64];
pub type ProgramId = [u32; 8];
pub type AccountId = [u8; 32];
pub type Nonce = u128;
pub type PublicKey = [u8; 32];

#[repr(C)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub bedrock_status: BedrockStatus,
    pub bedrock_parent_id: MsgId,
}

#[repr(C)]
pub struct BlockOpt {
    pub block: *const Block,
    pub is_ok: bool,
} 

#[repr(C)]
pub struct PublicMessage {
    pub program_id: ProgramId,
    pub account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub instruction_data: Vec<u32>,
}

#[repr(C)]
pub struct PublicTransactionBody {
    pub hash: HashType,
    pub message: PublicMessage,
    pub witness_set: Vec<(Signature, PublicKey)>,
}

#[repr(C)]
pub struct PrivateTransactionBody {
    
}

#[repr(C)]
pub struct ProgramDeploymentTransactionBody {
    
}

#[repr(C)]
pub struct TransactionBody {
    pub public_body: *const PublicTransactionBody,
    pub private_body: *const PrivateTransactionBody,
    pub program_deployment_body: *const ProgramDeploymentTransactionBody,
}

#[repr(C)]
pub struct Transaction {
    pub body: TransactionBody,
    pub kind: TransactionKind,
}

#[repr(C)]
pub struct BlockBody {
    pub txs: *const Transaction,
    pub len: usize,
}

impl Default for BlockBody {
    fn default() -> Self {
        Self {
            txs: std::ptr::null_mut(),
            len: 0,
        }
    }
}

#[repr(C)]
pub struct BlockHeader {
    pub block_id: BlockId,
    pub prev_block_hash: HashType,
    pub hash: HashType,
    pub timestamp: Timestamp,
    pub signature: Signature,
} 

#[repr(C)]
pub enum BedrockStatus {
    Pending = 0x0,
    Safe,
    Finalized,
}

#[repr(C)]
pub enum TransactionKind {
    Public = 0x0,
    Private,
    ProgramDeploy,
}