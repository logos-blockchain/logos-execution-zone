# Reimplementation of the bounds in b-wagn/hashsig-parameters (lower_bounds.py, parameters/sha.py)
import math
l2=math.log2
def rb(x): return math.ceil(x/8)*8
def hash_len(C,Q,logL,v,cs): return max(math.ceil(C+l2(5)+2*cs+logL+l2(v)), math.ceil(2*(Q+l2(5)+2*cs+logL+l2(v)+l2(12))))
def par_len(C,Q): return max(math.ceil(C+l2(5)+3), math.ceil(2*(Q+l2(5)+2)+5))
def rand_ts(C,Q,logL,logK): return max(math.ceil(C+l2(5)+logL+logK+1), math.ceil(2*(Q+l2(5)+l2(3)+logK)+logL))
def rand_w(C,Q,logL): return max(math.ceil(C+l2(5)+logL+1), math.ceil(2*(Q+l2(5)+l2(3))+logL))
def mh_len(C,Q): return max(math.ceil(C+l2(5)+1), math.ceil(2*(Q+l2(5)+1)+3))
for (C,Q,lvl) in [(128,64,"L1"),(256,128,"L5")]:
  for logL,mode in [(0,"fresh"),(32,"fixed")]:
    for cs in [2,4,8]:
      base=2**cs; logK=12
      mh=rb(mh_len(C,Q)); v=math.ceil(mh/cs)
      n=rb(hash_len(C,Q,logL,v,cs)); p=rb(par_len(C,Q)); r=rb(rand_ts(C,Q,logL,logK))
      for off in [1.0,1.1]:
        T=math.ceil(off*v*(base-1)/2); steps=v*(base-1)-T
        print(f"{lvl} {mode} TSW  w={base:3d} v={v:3d} T={T:5d} off={off} n={n//8}B P={p//8}B rho={r//8}B mh={v*cs}b sig={(v*n+r)//8}B verify_steps={steps} {'OK' if max(n,p,r,v*cs)<=256 else '>256b'}")
      kap=rb(mh_len(C,Q)); vm=math.ceil(kap/cs); vc=1+math.floor(math.log(vm*(base-1),base)); v=vm+vc
      n=rb(hash_len(C,Q,logL,v,cs)); r=rb(rand_w(C,Q,logL))
      print(f"{lvl} {mode} WOTS w={base:3d} v={v:3d} n={n//8}B rho={r//8}B sig={(v*n+r)//8}B avg_verify_steps~{v*(base-1)//2} {'OK' if max(n,r)<=256 else '>256b'}")
