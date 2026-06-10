use ruint::{aliases::U512, uint};

pub const PRICE_SCALE: u128 = 100_000_000;
pub const MAX_TICK: i32 = 887_272;

fn sqrt_ratio_at_tick(tick: i32) -> U512 {
    let abs_tick = tick.unsigned_abs();
    assert!(abs_tick <= MAX_TICK as u32, "Tick out of range");

    let mut ratio = if abs_tick & 0x1 != 0 {
        uint!(0xfffcb933bd6fad37aa2d162d1a594001_U512)
    } else {
        uint!(0x100000000000000000000000000000000_U512)
    };

    let factors: [(u32, U512); 19] = [
        (0x2, uint!(0xfff97272373d413259a46990580e213a_U512)),
        (0x4, uint!(0xfff2e50f5f656932ef12357cf3c7fdcc_U512)),
        (0x8, uint!(0xffe5caca7e10e4e61c3624eaa0941cd0_U512)),
        (0x10, uint!(0xffcb9843d60f6159c9db58835c926644_U512)),
        (0x20, uint!(0xff973b41fa98c081472e6896dfb254c0_U512)),
        (0x40, uint!(0xff2ea16466c96a3843ec78b326b52861_U512)),
        (0x80, uint!(0xfe5dee046a99a2a811c461f1969c3053_U512)),
        (0x100, uint!(0xfcbe86c7900a88aedcffc83b479aa3a4_U512)),
        (0x200, uint!(0xf987a7253ac413176f2b074cf7815e54_U512)),
        (0x400, uint!(0xf3392b0822b70005940c7a398e4b70f3_U512)),
        (0x800, uint!(0xe7159475a2c29b7443b29c7fa6e889d9_U512)),
        (0x1000, uint!(0xd097f3bdfd2022b8845ad8f792aa5825_U512)),
        (0x2000, uint!(0xa9f746462d870fdf8a65dc1f90e061e5_U512)),
        (0x4000, uint!(0x70d869a156d2a1b890bb3df62baf32f7_U512)),
        (0x8000, uint!(0x31be135f97d08fd981231505542fcfa6_U512)),
        (0x10000, uint!(0x9aa508b5b7a84e1c677de54f3e99bc9_U512)),
        (0x20000, uint!(0x5d6af8dedb81196699c329225ee604_U512)),
        (0x40000, uint!(0x2216e584f5fa1ea926041bedfe98_U512)),
        (0x80000, uint!(0x48a170391f7dc42444e8fa2_U512)),
    ];

    for (mask, factor) in factors {
        if abs_tick & mask != 0 {
            ratio = (ratio * factor) >> 128;
        }
    }

    if tick > 0 {
        let u256_max = (uint!(1_U512) << 256) - uint!(1_U512);
        ratio = u256_max / ratio;
    }

    let remainder = ratio & uint!(0xffffffff_U512);
    let round = if remainder.is_zero() {
        uint!(0_U512)
    } else {
        uint!(1_U512)
    };

    (ratio >> 32) + round
}

#[must_use]
pub fn tick_to_price(tick: i32) -> u128 {
    let sqrt = sqrt_ratio_at_tick(tick);
    let price: U512 = (sqrt * sqrt * U512::from(PRICE_SCALE)) >> 192;

    let limbs = price.as_limbs();
    if limbs[2..].iter().any(|&l| l != 0) {
        u128::MAX
    } else {
        u128::from(limbs[0]) | (u128::from(limbs[1]) << 64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_zero_is_unit_price() {
        assert_eq!(tick_to_price(0), PRICE_SCALE);
    }

    #[test]
    fn tick_to_price_matches_known_value() {
        let price = tick_to_price(600);

        assert!(
            (106_000_000..107_000_000).contains(&price),
            "1.0001^600 should be ~1.0618, got {price}"
        );
    }

    #[test]
    fn negative_tick_is_below_unit() {
        let price = tick_to_price(-600);

        assert!(
            (94_000_000..95_000_000).contains(&price),
            "1.0001^-600 should be ~0.9418, got {price}"
        );
    }

    #[test]
    fn extreme_ticks_do_not_panic() {
        let _high = tick_to_price(MAX_TICK);
        let low = tick_to_price(-MAX_TICK);

        assert!(low < PRICE_SCALE);
    }
}
