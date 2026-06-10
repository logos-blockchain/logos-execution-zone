use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::Data;

pub const SOURCE_TWAP: u32 = 1;
pub const SOURCE_REDSTONE: u32 = 2;

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct PriceAccount {
    pub base_asset: [u8; 32],
    pub quote_asset: [u8; 32],
    pub price: u128,
    pub timestamp_ms: u64,
    pub source_id: u32,
    pub confidence: u128,
}

impl TryFrom<&Data> for PriceAccount {
    type Error = std::io::Error;

    fn try_from(data: &Data) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&PriceAccount> for Data {
    fn from(price: &PriceAccount) -> Self {
        let mut data = Vec::with_capacity(std::mem::size_of_val(price));

        BorshSerialize::serialize(price, &mut data).expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Price account encoded data should fit into Data")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeError {
    PairMismatch,
    Stale,
    Unavailable,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diagnostics {
    pub fallback_used: bool,
    pub divergence_detected: bool,
}

#[must_use = "the recommended response to an error is to refuse the action, not fall back to a default"]
pub fn consume(
    price: &PriceAccount,
    base_asset: [u8; 32],
    quote_asset: [u8; 32],
    max_age_ms: u64,
    now_ms: u64,
) -> Result<u128, ConsumeError> {
    if price.base_asset != base_asset || price.quote_asset != quote_asset {
        return Err(ConsumeError::PairMismatch);
    }
    if price.price == 0 {
        return Err(ConsumeError::Unavailable);
    }
    if now_ms.saturating_sub(price.timestamp_ms) > max_age_ms {
        return Err(ConsumeError::Stale);
    }

    Ok(price.price)
}

pub fn consume_multi(
    primary: &PriceAccount,
    fallback: &PriceAccount,
    base_asset: [u8; 32],
    quote_asset: [u8; 32],
    max_age_ms: u64,
    now_ms: u64,
    max_divergence_bps: u128,
) -> (Result<u128, ConsumeError>, Diagnostics) {
    let primary_result = consume(primary, base_asset, quote_asset, max_age_ms, now_ms);
    let fallback_result = consume(fallback, base_asset, quote_asset, max_age_ms, now_ms);

    let mut diagnostics = Diagnostics::default();

    if let (Ok(p), Ok(f)) = (&primary_result, &fallback_result) {
        let (hi, lo) = (*p.max(f), *p.min(f));
        if lo > 0 && (hi - lo) * 10_000 / lo > max_divergence_bps {
            diagnostics.divergence_detected = true;
        }
    }

    match primary_result {
        Ok(value) => (Ok(value), diagnostics),
        Err(_) => {
            diagnostics.fallback_used = true;
            (fallback_result, diagnostics)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BTC: [u8; 32] = [1; 32];
    const USD: [u8; 32] = [2; 32];

    fn price(value: u128, ts: u64) -> PriceAccount {
        PriceAccount {
            base_asset: BTC,
            quote_asset: USD,
            price: value,
            timestamp_ms: ts,
            source_id: SOURCE_TWAP,
            confidence: 0,
        }
    }

    #[test]
    fn fresh_matching_price_is_returned() {
        assert_eq!(consume(&price(100, 1_000), BTC, USD, 5_000, 4_000), Ok(100));
    }

    #[test]
    fn pair_mismatch_is_rejected() {
        assert_eq!(
            consume(&price(100, 1_000), USD, BTC, 5_000, 4_000),
            Err(ConsumeError::PairMismatch)
        );
    }

    #[test]
    fn stale_price_is_rejected() {
        assert_eq!(
            consume(&price(100, 1_000), BTC, USD, 5_000, 10_000),
            Err(ConsumeError::Stale)
        );
    }

    #[test]
    fn zero_price_is_unavailable() {
        assert_eq!(
            consume(&price(0, 1_000), BTC, USD, 5_000, 4_000),
            Err(ConsumeError::Unavailable)
        );
    }

    #[test]
    fn falls_back_when_primary_stale() {
        let (result, diag) = consume_multi(
            &price(100, 0),
            &price(101, 9_000),
            BTC,
            USD,
            5_000,
            10_000,
            500,
        );
        assert_eq!(result, Ok(101));
        assert!(diag.fallback_used);
    }

    #[test]
    fn divergence_is_flagged_but_does_not_gate() {
        let (result, diag) = consume_multi(
            &price(100, 9_000),
            &price(200, 9_000),
            BTC,
            USD,
            5_000,
            10_000,
            500,
        );
        assert_eq!(result, Ok(100));
        assert!(diag.divergence_detected);
        assert!(!diag.fallback_used);
    }
}
