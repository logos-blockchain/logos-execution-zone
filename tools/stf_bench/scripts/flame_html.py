"""Folded stacks -> one self-contained HTML flamegraph (click a frame to zoom, type to search).

Usage: flame_html.py <in.folded> <out.html> <title>. Frames under 0.02% of the total are dropped.
"""
import json, re, sys

HASH = re.compile(r"\[[0-9a-f]{16}\]")
def clean(name):
    return HASH.sub("", name)

root = {"n": "all", "v": 0, "c": {}}
for line in open(sys.argv[1]):
    stack, _, count = line.rstrip("\n").rpartition(" ")
    count = int(count)
    root["v"] += count
    node = root
    for frame in stack.split(";"):
        frame = clean(frame)
        child = node["c"].get(frame)
        if child is None:
            child = node["c"][frame] = {"n": frame, "v": 0, "c": {}}
        child["v"] += count
        node = child

FLOOR = root["v"] * 0.0002
def pack(node):
    kids = [c for c in sorted(node["c"].values(), key=lambda c: -c["v"]) if c["v"] >= FLOOR]
    return [node["n"], node["v"], [pack(c) for c in kids]]

title = sys.argv[3]
html = """<!doctype html><meta charset="utf-8"><title>%TITLE%</title>
<style>
body{margin:0;font:12px ui-monospace,Menlo,monospace;background:#fff;color:#111}
header{padding:10px 14px;border-bottom:1px solid #ddd;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
h1{font-size:14px;margin:0}#info{color:#555;flex:1;min-width:200px}
input{font:inherit;padding:3px 6px}#g{position:relative;margin:8px 14px}
.f{position:absolute;height:17px;line-height:17px;overflow:hidden;white-space:nowrap;padding:0 3px;box-sizing:border-box;
border-right:1px solid #fff;border-bottom:1px solid #fff;cursor:pointer;font-size:11px}
.f.hit{outline:2px solid #00f;outline-offset:-2px}
</style>
<header><h1>%TITLE%</h1><input id="q" placeholder="search, e.g. schnorr"><span id="info">click a frame to zoom; click the bottom bar to reset</span></header>
<div id="g"></div>
<script>
const data=%DATA%, total=data[1], H=18, g=document.getElementById('g'), info=document.getElementById('info');
let focus=data, depth=0;
function color(n){if(n.startsWith('['))return'#c9c9c9';let h=0;for(const ch of n)h=(h*31+ch.charCodeAt(0))>>>0;
 const k=/k256|schnorr|elliptic|bigint/i.test(n)?0:/sha|hash|Digest/i.test(n)?1:/borsh|serialize|deserial/i.test(n)?2:/stf_smt|Node/.test(n)?3:4;
 const base=[[8,85],[200,60],[280,45],[140,45],[30,80]][k];return`hsl(${base[0]+(h%25)},${base[1]}%,${62+(h%14)}%)`}
function maxDepth(n){let d=0;for(const c of n[2])d=Math.max(d,maxDepth(c));return d+1}
function render(){g.innerHTML='';const W=g.clientWidth,D=maxDepth(focus)+depth;g.style.height=(D*H+4)+'px';
 const q=document.getElementById('q').value.toLowerCase();let found=0;
 function draw(n,x,w,d){if(w<0.5)return;const el=document.createElement('div');el.className='f';
  el.style.left=x+'px';el.style.width=w+'px';el.style.top=((D-d-1)*H)+'px';el.style.background=color(n[0]);
  if(w>30)el.textContent=n[0];const pct=(100*n[1]/total).toFixed(2);
  el.title=`${n[0]}\\n${n[1].toLocaleString()} cycles, ${pct}% of the block`;
  if(q&&n[0].toLowerCase().includes(q)){el.classList.add('hit')}
  el.onclick=e=>{e.stopPropagation();if(n===focus&&d===depth){reset();return}zoom(n,d)};
  el.onmouseenter=()=>info.textContent=`${n[0]} — ${n[1].toLocaleString()} cycles (${pct}%)`;
  g.appendChild(el);let cx=x;for(const c of n[2]){const cw=w*c[1]/n[1];draw(c,cx,cw,d+1);cx+=cw}}
 if(q){(function count(n){if(n[0].toLowerCase().includes(q)){found+=n[1];return}for(const c of n[2])count(c)})(focus);
  info.textContent=`"${q}": ${found.toLocaleString()} cycles (${(100*found/total).toFixed(1)}% of the block)`}
 draw(focus,0,W,depth)}
let path=[];function zoom(n,d){focus=n;depth=d;render()}
function reset(){focus=data;depth=0;render()}
document.getElementById('q').oninput=render;window.onresize=render;render();
</script>"""
html = html.replace("%TITLE%", title).replace("%DATA%", json.dumps(pack(root), separators=(",", ":")))
open(sys.argv[2], "w").write(html)

# Inclusive totals for the frames that matter, counted once per stack.
def inclusive(pattern):
    rx = re.compile(pattern)
    total = 0
    for line in open(sys.argv[1]):
        stack, _, count = line.rstrip("\n").rpartition(" ")
        if any(rx.search(clean(f)) for f in stack.split(";")):
            total += int(count)
    return total
print("total", root["v"])
for label, pattern in [
    ("paging", r"^\[Page"),
    ("schnorr verify", r"schnorr.*verify|verify_prehash"),
    ("pubkey decode (lift_x)", r"lift_x|VerifyingKey.*from_bytes"),
    ("sha256", r"sha2|sha::|Sha256|compress256"),
    ("borsh", r"borsh"),
    ("apply_block", r"apply_block"),
    ("smt", r"stf_smt"),
    ("env::verify", r"env::verify|guest::env::verify"),
]:
    v = inclusive(pattern)
    print(f"{label:24} {v:>10,} {100*v/root['v']:5.1f}%")
