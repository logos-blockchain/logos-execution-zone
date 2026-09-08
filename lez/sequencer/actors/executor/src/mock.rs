#![expect(
    clippy::struct_field_names,
    reason = "`handle*` prefix is used for convenience with `Message` trait"
)]

use common::{block::Block, transaction::LeeTransaction};
use kameo::{
    Actor, Reply,
    actor::ActorRef,
    message::{Context, Message},
    reply::DelegatedReply,
};
use lee_core::{
    BlockId, CommitmentSetDigest, MembershipProof,
    account::{Balance, Nonce},
};

use crate::{
    ExecutorActorTrait, Result,
    error::Error,
    protocol::{
        FeeStateQuote, GetAccount, GetAccountBalance, GetAccountNonces, GetAccountReply,
        GetAccountView, GetBlock, GetBlockRange, GetChannelId, GetChannelIdReply,
        GetCrossZoneDeadLetters, GetCrossZoneDeadLettersReply, GetFeeQuote, GetLastBlockId,
        GetProofsAndRoot, GetTransaction, ProduceBlock, RequeueCrossZoneDeadLetter,
        RequeueCrossZoneDeadLetterReply, Transaction,
    },
};

mockall::mock! {
    pub ExecutorActor {
        pub fn handle_produce_block(
            &mut self,
            msg: ProduceBlock,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_transaction(
            &mut self,
            msg: Transaction,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_block(
            &mut self,
            msg: GetBlock,
            ctx: &mut Context<Self, Result<Option<Block>>>
        ) -> Result<Option<Block>>;

        pub fn handle_get_block_range(
            &mut self,
            msg: GetBlockRange,
            ctx: &mut Context<Self, DelegatedReply<Result<Vec<Block>>>>
        ) -> DelegatedReply<Result<Vec<Block>>>;

        pub fn handle_get_last_block_id(
            &mut self,
            msg: GetLastBlockId,
            ctx: &mut Context<Self, Result<BlockId>>
        ) -> Result<BlockId>;

        pub fn handle_get_account_balance(
            &mut self,
            msg: GetAccountBalance,
            ctx: &mut Context<Self, Balance>
        ) -> Balance;

        pub fn handle_get_transaction(
            &mut self,
            msg: GetTransaction,
            ctx: &mut Context<Self, Result<Option<(LeeTransaction, BlockId)>>>
        ) -> Result<Option<(LeeTransaction, BlockId)>>;

        pub fn handle_get_account_nonces(
            &mut self,
            msg: GetAccountNonces,
            ctx: &mut Context<Self, Vec<Nonce>>
        ) -> Vec<Nonce>;

        pub fn handle_get_proofs_and_root(
            &mut self,
            msg: GetProofsAndRoot,
            ctx: &mut Context<Self, (Vec<Option<MembershipProof>>, CommitmentSetDigest)>
        ) -> (Vec<Option<MembershipProof>>, CommitmentSetDigest);

        pub fn handle_get_account(
            &mut self,
            msg: GetAccount,
            ctx: &mut Context<Self, GetAccountReply>
        ) -> GetAccountReply;

        pub fn handle_get_account_view(
            &mut self,
            msg: GetAccountView,
            ctx: &mut Context<Self, GetAccountReply>
        ) -> GetAccountReply;

        pub fn handle_get_channel_id(
            &mut self,
            msg: GetChannelId,
            ctx: &mut Context<Self, GetChannelIdReply>
        ) -> GetChannelIdReply;

        pub fn handle_get_cross_zone_dead_letters(
            &mut self,
            msg: GetCrossZoneDeadLetters,
            ctx: &mut Context<Self, Result<GetCrossZoneDeadLettersReply>>
        ) -> Result<GetCrossZoneDeadLettersReply>;

        pub fn handle_requeue_cross_zone_dead_letter(
            &mut self,
            msg: RequeueCrossZoneDeadLetter,
            ctx: &mut Context<Self, Result<RequeueCrossZoneDeadLetterReply>>
        ) -> Result<RequeueCrossZoneDeadLetterReply>;

        pub fn handle_get_fee_quote(
            &mut self,
            msg: GetFeeQuote,
            ctx: &mut Context<Self, FeeStateQuote>
        ) -> FeeStateQuote;
    }
}

impl ExecutorActorTrait for MockExecutorActor {}

impl Actor for MockExecutorActor {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        Ok(args)
    }
}

/// Special message to trigger [`MockExecutorActor::checkpoint()`].
pub struct Checkpoint;

impl Message<Checkpoint> for MockExecutorActor {
    type Reply = ();

    async fn handle(
        &mut self,
        Checkpoint: Checkpoint,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.checkpoint();
    }
}

/// Special message to [`std::mem::replace()`] the inner state of [`MockExecutorActor`] with a new
/// one, returning old state.
/// This is useful for testing, to swap in a new mock with different expectations.
pub struct Replace {
    pub mock: MockExecutorActor,
}

#[derive(Reply)]
pub struct ReplaceReply {
    pub old_mock: MockExecutorActor,
}

impl Message<Replace> for MockExecutorActor {
    type Reply = ReplaceReply;

    async fn handle(
        &mut self,
        Replace { mock }: Replace,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let old_mock = std::mem::replace(self, mock);
        ReplaceReply { old_mock }
    }
}

impl Message<Transaction> for MockExecutorActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: Transaction,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_transaction(msg, ctx)
    }
}

impl Message<ProduceBlock> for MockExecutorActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: ProduceBlock,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_produce_block(msg, ctx)
    }
}

impl Message<GetBlock> for MockExecutorActor {
    type Reply = Result<Option<Block>>;

    async fn handle(&mut self, msg: GetBlock, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.handle_get_block(msg, ctx)
    }
}

impl Message<GetBlockRange> for MockExecutorActor {
    type Reply = DelegatedReply<Result<Vec<Block>>>;

    async fn handle(
        &mut self,
        msg: GetBlockRange,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_block_range(msg, ctx)
    }
}

impl Message<GetLastBlockId> for MockExecutorActor {
    type Reply = Result<BlockId>;

    async fn handle(
        &mut self,
        msg: GetLastBlockId,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_last_block_id(msg, ctx)
    }
}

impl Message<GetAccountBalance> for MockExecutorActor {
    type Reply = Balance;

    async fn handle(
        &mut self,
        msg: GetAccountBalance,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_account_balance(msg, ctx)
    }
}

impl Message<GetTransaction> for MockExecutorActor {
    type Reply = Result<Option<(LeeTransaction, BlockId)>>;

    async fn handle(
        &mut self,
        msg: GetTransaction,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_transaction(msg, ctx)
    }
}

impl Message<GetAccountNonces> for MockExecutorActor {
    type Reply = Vec<Nonce>;

    async fn handle(
        &mut self,
        msg: GetAccountNonces,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_account_nonces(msg, ctx)
    }
}

impl Message<GetProofsAndRoot> for MockExecutorActor {
    type Reply = (Vec<Option<MembershipProof>>, CommitmentSetDigest);

    async fn handle(
        &mut self,
        msg: GetProofsAndRoot,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_proofs_and_root(msg, ctx)
    }
}

impl Message<GetAccount> for MockExecutorActor {
    type Reply = GetAccountReply;

    async fn handle(
        &mut self,
        msg: GetAccount,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_account(msg, ctx)
    }
}

impl Message<GetAccountView> for MockExecutorActor {
    type Reply = GetAccountReply;

    async fn handle(
        &mut self,
        msg: GetAccountView,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_account_view(msg, ctx)
    }
}

impl Message<GetChannelId> for MockExecutorActor {
    type Reply = GetChannelIdReply;

    async fn handle(
        &mut self,
        msg: GetChannelId,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_channel_id(msg, ctx)
    }
}

impl Message<GetCrossZoneDeadLetters> for MockExecutorActor {
    type Reply = Result<GetCrossZoneDeadLettersReply>;

    async fn handle(
        &mut self,
        msg: GetCrossZoneDeadLetters,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_cross_zone_dead_letters(msg, ctx)
    }
}

impl Message<RequeueCrossZoneDeadLetter> for MockExecutorActor {
    type Reply = Result<RequeueCrossZoneDeadLetterReply>;

    async fn handle(
        &mut self,
        msg: RequeueCrossZoneDeadLetter,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_requeue_cross_zone_dead_letter(msg, ctx)
    }
}

impl Message<GetFeeQuote> for MockExecutorActor {
    type Reply = FeeStateQuote;

    async fn handle(
        &mut self,
        msg: GetFeeQuote,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_fee_quote(msg, ctx)
    }
}
