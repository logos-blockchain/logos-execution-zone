# FORS(k, a) after q signatures with the same FORS key: per tree, a fresh index is covered
# with prob 1-(1-2^-a)^q; forgery needs all k covered.
# Mini SLH-DSA with K leaves and Q total signatures: forged message lands on a random leaf
# whose load is Bin(Q, 1/K).
import math
def p_fors(k, a, q): return (1 - (1 - 2**-a)**q)**k if q else 0.0
def p_mini(k, a, K, Q):
    return sum(math.comb(Q, q) * (1/K)**q * (1-1/K)**(Q-q) * p_fors(k, a, q) for q in range(Q+1))
b = lambda p: -math.log2(p)
print("| FORS params | q=1 | q=2 | q=4 | q=8 | mini K=8, Q=8 total | mini K=8, Q=16 total |")
print("|---|---:|---:|---:|---:|---:|---:|")
for name, k, a in [("128f (k=33, a=6)", 33, 6), ("128s (k=14, a=12)", 14, 12)]:
    print(f"| {name} | " + " | ".join(f"{b(p_fors(k,a,q)):.0f}" for q in (1,2,4,8)) +
          f" | {b(p_mini(k,a,8,8)):.0f} | {b(p_mini(k,a,8,16)):.0f} |")
