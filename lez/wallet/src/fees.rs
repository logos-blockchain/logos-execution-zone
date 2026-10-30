//! Fees a send declares, and what a dry run reports instead of sending.

use lee::{AccountId, FeeDeclaration};
use sequencer_service_rpc::FeeStateQuote;

/// The in-proof fee of a privacy-preserving transaction.
///
/// Its proof debits `reserve` from `payer`. The surplus over the fee charged is refunded to
/// `refund_to`, or to the payer's alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateFee {
    pub payer: AccountId,
    pub reserve: u128,
    pub refund_to: Option<AccountId>,
}

/// What every send declares in place of the wallet's defaults; `None` keeps the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeeParams {
    /// Public: the execution gas limit, else the measured cycles plus the configured margin.
    pub gas_limit: Option<u64>,
    /// Public: the fee cap, else the reserve at the headroom's base fees plus the tip.
    pub max_fee: Option<u128>,
    /// Public: the tip, charged on top of the base fees.
    pub tip: u64,
    /// Blocks of steepest base fee climb a fee is priced to cover, else the configured ones.
    pub headroom_blocks: Option<u64>,
    /// Private: the owned private account paying every in-proof fee, unless a send names its
    /// own, else each send picks its payer.
    pub payer: Option<AccountId>,
    /// Private: the public account the surplus is refunded to, else the payer's alias.
    pub refund_to: Option<AccountId>,
}

/// The fee a send declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredFee {
    Public(FeeDeclaration),
    Private(PrivateFee),
}

/// What a dry run simulated a send to cost at the head fee state.
#[derive(Debug, Clone)]
pub enum DryRunReport {
    Public {
        fee: FeeDeclaration,
        quote: FeeStateQuote,
        cycles: u64,
        /// The transaction's wire size, priced at the storage base fee.
        wire_bytes: u64,
        /// Includes the tip.
        fee_at_head: u128,
        /// What admission holds from the payer, priced at the gas limit: the least `max_fee`
        /// the sequencer accepts.
        reserve_at_head: u128,
        /// Why the action reverts; a reverted action still pays its fee.
        revert_reason: Option<String>,
    },
    Private {
        fee: PrivateFee,
        quote: FeeStateQuote,
        /// Cycles of the public part.
        cycles: u64,
        fee_at_head: u128,
        /// Blocks of steepest base fee climb the reserve covers, and the base fees after them.
        headroom_blocks: u64,
        exec_ceiling: u64,
        stor_ceiling: u64,
        /// The fee at the ceilings; the reserve is this clamped to the payer's balance.
        headroom_reserve: u128,
        /// Pending credits claimed before the root.
        claims: usize,
        /// The part of the claims reaching the payer.
        swept: u128,
    },
}

impl DryRunReport {
    #[must_use]
    pub const fn fee(&self) -> DeclaredFee {
        match self {
            Self::Public { fee, .. } => DeclaredFee::Public(*fee),
            Self::Private { fee, .. } => DeclaredFee::Private(*fee),
        }
    }

    #[must_use]
    pub const fn quote(&self) -> &FeeStateQuote {
        match self {
            Self::Public { quote, .. } | Self::Private { quote, .. } => quote,
        }
    }
}

impl std::fmt::Display for DryRunReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let FeeStateQuote {
            height,
            base_fee_exec,
            base_fee_stor,
            ..
        } = self.quote();
        match self {
            Self::Public {
                fee,
                cycles,
                wire_bytes,
                fee_at_head,
                reserve_at_head,
                revert_reason,
                ..
            } => {
                writeln!(f, "Dry run: nothing sent")?;
                writeln!(f, "  fee payer:        {}", fee.payer)?;
                writeln!(f, "  declared gas:     {}", fee.gas_limit)?;
                writeln!(f, "  metered cycles:   {cycles}")?;
                writeln!(f, "  wire bytes:       {wire_bytes}")?;
                writeln!(
                    f,
                    "  base fees:        exec {base_fee_exec} / stor {base_fee_stor} (height \
                     {height})"
                )?;
                writeln!(f, "  fee at head:      {fee_at_head} (tip {})", fee.tip)?;
                writeln!(
                    f,
                    "  reserve at head:  {reserve_at_head} (max fee {})",
                    fee.max_fee
                )?;
                match revert_reason {
                    Some(reason) => {
                        write!(f, "  action REVERTS:   {reason} (fee is still charged)")
                    }
                    None => write!(f, "  action:           applies"),
                }
            }
            Self::Private {
                fee,
                cycles,
                fee_at_head,
                headroom_blocks,
                exec_ceiling,
                stor_ceiling,
                headroom_reserve,
                claims,
                swept,
                ..
            } => {
                writeln!(f, "Dry run: nothing proven or sent")?;
                writeln!(f, "  public cycles:  {cycles}")?;
                writeln!(
                    f,
                    "  base fees:      exec {base_fee_exec} / stor {base_fee_stor} (height \
                     {height})"
                )?;
                writeln!(f, "  fee at head:    {fee_at_head}")?;
                writeln!(
                    f,
                    "  headroom:       {headroom_blocks} blocks, up to exec {exec_ceiling} / \
                     stor {stor_ceiling} ({headroom_reserve})"
                )?;
                writeln!(f, "  reserve:        {} (surplus refunded)", fee.reserve)?;
                writeln!(f, "  fee payer:      {}", fee.payer)?;
                writeln!(
                    f,
                    "  claims:         {claims} pending credit(s), {swept} to the payer"
                )?;
                write!(
                    f,
                    "  refund to:      {}",
                    fee.refund_to
                        .map_or_else(|| "the payer's alias".to_owned(), |t| t.to_string())
                )
            }
        }
    }
}
