import math
l2=math.log2
C,Q,logL=192,96,0
rb=lambda x: math.ceil(x/8)
mh=math.ceil(max(C+l2(5)+1, 2*(Q+l2(5)+1)+3)/8)*8
p=rb(max(C+l2(5)+3,2*(Q+l2(5)+2)+5))
hl=lambda v,cs: rb(max(C+l2(5)+2*cs+logL+l2(v), 2*(Q+l2(5)+2*cs+logL+l2(v)+l2(12))))
for cs in (2,4,8):
    b=2**cs
    v=math.ceil(mh/cs); rho=rb(max(C+l2(5)+logL+12+1, 2*(Q+l2(5)+l2(3)+12)+logL))
    E=v*(b-1)/2
    print(f"TSW  w={b:3d} v={v} n={hl(v,cs)} P={p} rho={rho} T(E)={math.ceil(E)} T(1.1E)={math.ceil(1.1*E)}")
    vm=math.ceil(mh/cs); vc=1+math.floor(math.log(vm*(b-1),b)); v=vm+vc
    rho=rb(max(C+l2(5)+logL+1, 2*(Q+l2(5)+l2(3))+logL))
    print(f"Wcsum w={b:3d} vm={vm} vc={vc} v={v} n={hl(v,cs)} P={p} rho={rho}")
