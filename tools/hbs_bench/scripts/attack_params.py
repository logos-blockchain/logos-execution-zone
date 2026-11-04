# Attack-based L1 sizing (FIPS 205 style): n = 16 B. Encoding must keep >= 2^128 valid codewords.
import math
def count_sum(v, w, T):
    d=[1]
    for _ in range(v):
        nd=[0]*(len(d)+w-1)
        for s,c in enumerate(d):
            if c:
                for a in range(w): nd[s+a]+=c
        d=nd
    return d[T] if T<len(d) else 0
for cb in (2,4,8):
    w=2**cb
    for off in (1.0,1.1):
        for v in range(128//cb, 128//cb+8):
            T=math.ceil(off*v*(w-1)/2)
            b=math.log2(count_sum(v,w,T))
            if b>=128:
                print(f"TSW w={w} off={off} v={v} T={T} log2(codewords)={b:.1f} hash bits used={v*cb}")
                break
    vm=128//cb; vc=1+math.floor(math.log(vm*(w-1),w))
    print(f"Wcsum w={w} vm={vm} vc={vc} v={vm+vc}")
