# Security of a one-time Winternitz key after it signed q distinct (random) digests.
# Attacker learns, per chain, the lowest revealed position m_i = min over the q codewords.
# A forgery needs a fresh digest whose codeword c satisfies c_i >= m_i on every chain
# (and, for target-sum, sum c_i = T). P = Pr_digest[forgeable]; classical work ~ 1/P,
# quantum (Grover) ~ 1/sqrt(P), i.e. half the bits.
import math, random, sys, statistics
random.seed(1)

def box_conv(d, lo, hi, w):
    # convolve d with uniform mass 1/w on [lo, hi]
    out = [0.0] * (len(d) + hi)
    pre = [0.0]
    for x in d: pre.append(pre[-1] + x)
    for s in range(len(out)):
        a, b = max(0, s - hi), min(len(d) - 1, s - lo)
        if a <= b: out[s] = (pre[b + 1] - pre[a]) / w
    return out

_N = {}
def ts_counts(v, w):
    if (v, w) not in _N:
        N = [[1.0]]
        for _ in range(v): N.append(box_conv(N[-1], 0, w - 1, w))
        _N[(v, w)] = N
    return _N[(v, w)]

def ts_codeword(v, w, T):
    N = ts_counts(v, w); x = []; s = T
    for k in range(v, 0, -1):
        rest = N[k - 1]
        p = [rest[s - a] if 0 <= s - a < len(rest) else 0.0 for a in range(w)]
        a = random.choices(range(w), weights=p)[0]; x.append(a); s -= a
    return x

def ts_P(m, w, T):
    d = [1.0]
    for mi in m: d = box_conv(d, mi, w - 1, w)
    return d[T] if T < len(d) else 0.0

def wc_codeword(vm, vc, w):
    x = [random.randrange(w) for _ in range(vm)]
    cs = sum(w - 1 - a for a in x)
    for _ in range(vc): x.append(cs % w); cs //= w
    return x

def wc_P(m, vm, vc, w):
    d = [1.0]
    for mi in m[:vm]: d = box_conv(d, 0, w - 1 - mi, w)   # distribution of checksum
    tot = 0.0
    for S, p in enumerate(d):
        if p == 0: continue
        s, ok = S, True
        for j in range(vc):
            if s % w < m[vm + j]: ok = False; break
            s //= w
        if ok: tot += p
    return tot

bits = lambda P: math.inf if P <= 0 else -math.log2(P)

sets = [
 ("L1 TSW w=16 T=E",      "ts", 36, 16, 270),
 ("L1 TSW w=16 T=1.1E",   "ts", 36, 16, 297),
 ("L1 TSW w=256 T=1.1E",  "ts", 18, 256, 2525),
 ("L1 W-csum w=16",       "wc", (36, 3), 16, None),
 ("L1 W-csum w=256",      "wc", (18, 2), 256, None),
 ("L3 TSW w=16 T=1.1E",   "ts", 52, 16, 429),
 ("L3 W-csum w=16",       "wc", (52, 3), 16, None),
 ("L5h TSW w=16 T=1.1E",  "ts", 64, 16, 528),
 ("L5h W-csum w=16",      "wc", (64, 3), 16, None),
 ("L5h TSW w=256 T=1.1E", "ts", 32, 256, 4488),
]
S = int(sys.argv[1]) if len(sys.argv) > 1 else 200
print("| parameter set | design (classical) | q=2 median | q=2 worst 10% | q=3 median | q=4 median |")
print("|---|---:|---:|---:|---:|---:|")
for name, kind, v, w, T in sets:
    res = {}
    for q in (2, 3, 4):
        bs = []
        for _ in range(S):
            if kind == "ts":
                cws = [ts_codeword(v, w, T) for _ in range(q)]
                m = [min(c) for c in zip(*cws)]; bs.append(bits(ts_P(m, w, T)))
            else:
                vm, vc = v
                cws = [wc_codeword(vm, vc, w) for _ in range(q)]
                m = [min(c) for c in zip(*cws)]; bs.append(bits(wc_P(m, vm, vc, w)))
        bs.sort()
        res[q] = (statistics.median(bs), bs[len(bs) // 10])
    design = {"L1": 128, "L3": 192, "L5h": 256}[name.split()[0]]
    print(f"| {name} | {design} | {res[2][0]:.0f} | {res[2][1]:.0f} | {res[3][0]:.0f} | {res[4][0]:.0f} |", flush=True)
