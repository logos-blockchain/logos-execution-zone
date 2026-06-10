# TWAP math — Uniswap references

The TWAP oracle math mirrors Uniswap v3/v4. This maps each piece of our code to
its authoritative source.

## 1. `tick_to_price` — price = 1.0001^tick (Uniswap TickMath)

Audited fixed-point exponentiation (bit-decomposition with precomputed
constants, Q64.96, tick range ±887272):

- v3: <https://github.com/Uniswap/v3-core/blob/main/contracts/libraries/TickMath.sol> — `getSqrtRatioAtTick` = `sqrt(1.0001^tick)`
- v4: <https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol>
- docs: <https://docs.uniswap.org/contracts/v3/reference/core/libraries/TickMath>

Our `twap_core::tick_to_price` is a simplified integer `pow` (exponentiation by
squaring in 1e18 fixed-point) that is correct for the PoC tick range. Production
should port the audited constants above for the full range and overflow safety.

## 2. Accumulator + `average_tick` — geometric-mean TWAP (Uniswap Oracle)

`tickCumulative = tick × elapsed time`; average tick over a window =
`ΔtickCumulative / Δtime`; the **arithmetic mean of ticks equals the geometric
mean of price** (sum of log-prices).

- code: <https://github.com/Uniswap/v3-core/blob/main/contracts/libraries/Oracle.sol> — `Observation`, `observe`/`consult`
- whitepaper (oracle/TWAP section): <https://app.uniswap.org/whitepaper-v3.pdf>
- docs: <https://docs.uniswap.org/concepts/protocol/oracle>
- step-by-step: <https://uniswapv3book.com/milestone_5/price-oracle.html>

Our model: `pool_stub_core::Observation { timestamp, tick_cumulative }`,
accumulate `tick × Δms` in `observe`, and `twap_core::average_tick =
Δtick_cumulative / Δms`.

## 3. `clamp_tick_delta` — ±9116 per-block truncation (Uniswap v4)

`MAX_ABS_TICK_MOVE = 9116` caps the tick move per block, truncating outliers to
resist oracle manipulation.

- <https://blog.uniswap.org/uniswap-v4-truncated-oracle-hook>
- <https://hacken.io/discover/uniswap-v4-truncated-oracle/>

Our `pool_stub_core::MAX_TICK_DELTA = 9_116` and `clamp_tick_delta`.
