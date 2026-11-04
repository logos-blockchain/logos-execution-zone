USABLE=1_048_576-2_048; BASE=222; PPE=235_338+1_000; PV=11_531; EX=3
rows=[
("Schnorr (today)",96,62.2),
("TSW w=256, L1 n=16, one-time",336,102.2),
("TSW w=256, L1 n=16, K=4",369,103.6),
("TSW w=256, L1 n=16, K=8",385,103.7),
("TSW w=256, L1 provable, one-time",475,104.9),
("TSW w=256, L1 provable, K=4",544,103.1),
("TSW w=256, L1 provable, K=8",568,104.5),
("TSW w=16, L1 n=16, one-time",592,11.9),
("TSW w=16, L1 n=16, K=4",625,12.2),
("TSW w=16, L1 n=16, K=8",641,12.2),
("TSW w=16, L1 provable, one-time",815,12.9),
("TSW w=16, L1 provable, K=4",898,13.3),
("TSW w=16, L1 provable, K=8",920,13.3),
("Checksum w=256, L1 n=16",336,120.2),
("Checksum w=16, L1 n=16",608,13.8),
("TSW w=16, L3, K=8",1736,19.4),
("FORS-128s leaf",2944,11.6),
("mini SLH-DSA 128s, K=8",3568,25.9),
]
print("| Option | Per-tx B | Transfer B | Public-only txs | +1 PPE txs | +1 PPE verify ms |")
for n,sb,v in rows:
    tx=BASE+4+sb; n0=USABLE//tx; n1=(USABLE-PPE-4-sb)//tx
    print(f"| {n} | {sb} | {tx} | {n0} | {n1} | {(PV+v+n1*(v+EX))/1000:.0f} |")
