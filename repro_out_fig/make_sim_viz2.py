#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全6006ノード・全12,800件・全期間のシミュレーション可視化HTMLを生成。"""
import csv, json, os, math
from collections import Counter, defaultdict

BASE = "/Volumes/public1/thesis/2026bachelor-af23/AF23027王毅恒/20260707175118"
ND   = f"{BASE}/no_defense/monitor_disable/n_payment12800/avg_pmt_amt=100/p_0_001"
M2   = f"{BASE}/avoid_low_reputation/monitor_method2/n_payment12800/avg_pmt_amt=100/monitor_count=10/p_0_001"
OUT  = "/Users/oukihisashi/CLionProjects/CLoTH-Gossip/repro_out_fig/cloth_sim_viz.html"

# ── ① ノード種別 ──────────────────────────────────────────────
print("ノード情報...")
malicious_set, monitor_set = set(), set()
with open(f"{M2}/reputation_dynamics.csv") as f:
    for r in csv.DictReader(f):
        if r["is_malicious"] == "1": malicious_set.add(int(r["node_id"]))
        if r["is_monitor"]  == "1": monitor_set.add(int(r["node_id"]))

# ── ② エッジ・次数 ───────────────────────────────────────────
print("エッジ読み込み...")
degree = Counter()
adj = defaultdict(set)           # 隣接リスト（経路描画に使用）
with open(f"{ND}/edges_output.csv") as f:
    for r in csv.DictReader(f):
        fn = int(r["from_node_id"]); tn = int(r["to_node_id"])
        degree[fn] += 1; degree[tn] += 1
        adj[fn].add(tn); adj[tn].add(fn)
print(f"  総ノード数: {len(degree)}, 総エッジ数（一方向）: {sum(len(v) for v in adj.values())//2}")

# ── ③ 全ノードの座標計算（次数ベース同心円 + 黄金角） ──────────
print("座標計算...")
PHI = (1 + 5**0.5) / 2
sorted_nodes = sorted(degree.keys(), key=lambda n: -degree[n])
N = len(sorted_nodes)
CANVAS_W, CANVAS_H = 900, 700
cx, cy = CANVAS_W / 2, CANVAS_H / 2
MAX_R = min(CANVAS_W, CANVAS_H) * 0.47

node_pos = {}   # node_id -> (x, y)
for rank, nid in enumerate(sorted_nodes):
    norm = rank / (N - 1) if N > 1 else 0
    r = MAX_R * (norm ** 0.45)                 # 中心が密集しすぎないよう調整
    angle = rank * 2 * math.pi / (PHI * PHI)  # 黄金角で均等分散
    node_pos[nid] = (
        round(cx + math.cos(angle) * r, 1),
        round(cy + math.sin(angle) * r, 1)
    )

# ── ④ 重要ノードに特別扱い（ハブを中心周辺に固定配置） ─────────
top_hubs   = [n for n, _ in degree.most_common(20) if n not in malicious_set][:12]
mal_hubs   = sorted(malicious_set, key=lambda n: -degree[n])[:8]
key_label  = set(top_hubs + mal_hubs + list(monitor_set))  # ラベル表示対象

# ── ⑤ 背景エッジ（上位50ハブ間のエッジのみ）─────────────────────
print("背景エッジ抽出...")
top50 = set(n for n, _ in degree.most_common(50))
bg_edges = []
seen_pairs = set()
for fn in top50:
    for tn in adj[fn]:
        if tn in top50:
            pair = (min(fn, tn), max(fn, tn))
            if pair not in seen_pairs:
                bg_edges.append([fn, tn])
                seen_pairs.add(pair)
print(f"  背景エッジ: {len(bg_edges)}本")

# ── ⑥ 全ペイメント読み込み ───────────────────────────────────
print("ペイメント読み込み...")
def load_all(path):
    rows = {}
    with open(f"{path}/payments_output.csv") as f:
        for r in csv.DictReader(f):
            if r["is_warmup"] not in ("0", "0.0", ""): continue
            rows[r["id"]] = r
    return rows

nd_raw = load_all(ND); m2_raw = load_all(M2)
T0     = min(int(r["start_time"]) for r in nd_raw.values())
T_END  = max(int(r["end_time"]) for r in nd_raw.values() if r["end_time"] not in ("", "-1"))
DURATION = T_END - T0
print(f"  T0={T0}, DURATION={DURATION/1000:.0f}s, n={len(nd_raw)}")

# ── ⑦ hops抽出（全ノードを保持）──────────────────────────────
def extract_hops(hist_raw):
    try:
        hist = json.loads(hist_raw)
        if not hist: return []
        last = hist[-1]
        seen = set(); result = []
        for hop in last.get("route", []):
            for k in ("from_node_id", "to_node_id"):
                n = hop.get(k)
                if n is not None:
                    nid = int(n)
                    if nid not in seen:
                        result.append(nid); seen.add(nid)
        return result
    except:
        return []

def process_payments(raw):
    key_pmts = []
    all_basic = []
    for r in raw.values():
        st  = int(r["start_time"]) - T0
        et_raw = r["end_time"]
        et  = int(et_raw) - T0 if et_raw not in ("", "-1") else st + 120000
        ok  = r["is_success"] == "1"
        atk = int(r["attack_delay_events"]) > 0
        pid = int(r["id"])
        all_basic.append({"id": pid, "st": st, "et": et, "ok": ok, "atk": atk})
        hops = extract_hops(r.get("attempts_history", "[]"))
        if hops:
            key_pmts.append({
                "id": pid, "st": st,
                "et": min(et, st + 60000),
                "ok": ok, "atk": atk,
                "hops": hops   # 全ノードIDを保持
            })
    return key_pmts, all_basic

print("  ペイメント処理中...")
nd_key, nd_all = process_payments(nd_raw)
m2_key, m2_all = process_payments(m2_raw)
print(f"  hops付き: nd={len(nd_key)}, m2={len(m2_key)}")

def sample_key(pmts, max_n=3000):
    pmts = sorted(pmts, key=lambda r: r["st"])
    if len(pmts) <= max_n: return pmts
    step = len(pmts) / max_n
    return [pmts[int(i * step)] for i in range(max_n)]

nd_key = sample_key(nd_key)
m2_key = sample_key(m2_key)
print(f"  サンプリング後: nd={len(nd_key)}, m2={len(m2_key)}")

# ── ⑧ 時系列集計（10秒ビン）────────────────────────────────────
BIN = 10000
bins = list(range(0, DURATION + BIN, BIN))
def make_ts(all_basic):
    ts = []
    for t in bins[:-1]:
        t1 = t + BIN
        ts.append({
            "t":  t,
            "an": sum(1 for r in all_basic if r["st"] <= t < r["et"] and not r["atk"]),
            "aa": sum(1 for r in all_basic if r["st"] <= t < r["et"] and r["atk"]),
            "ok": sum(1 for r in all_basic if r["et"] <= t1 and r["ok"]),
            "ac": sum(1 for r in all_basic if r["et"] <= t1 and r["atk"] and r["ok"]),
            "fc": sum(1 for r in all_basic if r["et"] <= t1 and not r["ok"]),
        })
    return ts

print("  時系列集計中...")
ts_nd = make_ts(nd_all); ts_m2 = make_ts(m2_all)
print(f"  ビン数={len(ts_nd)}")

# ── ⑨ ノード情報をコンパクトにまとめる ────────────────────────
# kind: 0=normal, 1=hub, 2=malicious, 3=monitor
def node_kind(nid):
    if nid in monitor_set:   return 3
    if nid in malicious_set: return 2
    if nid in top_hubs:      return 1
    return 0

nodes_compact = []
for nid in sorted(degree.keys()):
    x, y = node_pos[nid]
    nodes_compact.append([nid, round(x), round(y), degree[nid], node_kind(nid)])
    # [id, x, y, deg, kind]

# ラベル表示ノードの情報
label_nodes = []
for nid in key_label:
    x, y = node_pos[nid]
    label_nodes.append({
        "id": nid, "x": round(x), "y": round(y),
        "deg": degree[nid], "kind": node_kind(nid)
    })

# ── ⑩ JSONまとめ ────────────────────────────────────────────
data = {
    "nodes":      nodes_compact,   # [id,x,y,deg,kind]
    "label_nodes": label_nodes,
    "bg_edges":   bg_edges,
    "nd_key":     nd_key,
    "m2_key":     m2_key,
    "ts_nd":      ts_nd,
    "ts_m2":      ts_m2,
    "duration":   DURATION,
    "bin_ms":     BIN,
    "n_total":    len(nd_all),
    "mal_ids":    list(malicious_set),
    "mon_ids":    list(monitor_set),
}
data_json = json.dumps(data, ensure_ascii=False)
print(f"  JSONサイズ={len(data_json)/1024:.0f}KB")

# ── ⑪ HTML ───────────────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CLoTH-Gossip シミュレーション可視化</title>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--border:#30363d;
  --hub:#58a6ff;--mal:#f85149;--mon:#3fb950;--norm:#8b949e;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:#e6edf3;
     font-family:"Hiragino Sans","Helvetica Neue",sans-serif;
     font-size:13px;height:100vh;display:flex;flex-direction:column;overflow:hidden}}
header{{background:var(--panel);padding:8px 16px;border-bottom:1px solid var(--border);
        display:flex;align-items:center;gap:14px;flex-shrink:0;flex-wrap:wrap}}
header h1{{font-size:1rem;font-weight:700;color:var(--hub)}}
header .sub{{color:#8b949e;font-size:.78rem}}
.main{{display:flex;flex:1;overflow:hidden}}

#left{{flex:0 0 60%;display:flex;flex-direction:column;border-right:1px solid var(--border)}}
#net-wrap{{flex:1;position:relative;overflow:hidden}}
#net-canvas{{position:absolute;inset:0;width:100%;height:100%}}

#tl-wrap{{padding:5px 10px;background:#0d1117;border-top:1px solid var(--border);flex-shrink:0}}
#tl-outer{{width:100%;height:16px;background:#21262d;border-radius:3px;
           position:relative;cursor:pointer;overflow:hidden}}
#tl-fill{{position:absolute;inset:0 auto 0 0;background:rgba(88,166,255,.2);pointer-events:none}}
#tl-cur{{position:absolute;top:0;bottom:0;width:2px;background:#3fb950;pointer-events:none}}

#right{{flex:1;display:flex;flex-direction:column;overflow:hidden}}
#ctrl{{padding:8px 12px;background:var(--panel);border-bottom:1px solid var(--border);flex-shrink:0}}
.row{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:5px}}
.row:last-child{{margin-bottom:0}}
button{{background:#238636;color:#fff;border:none;border-radius:4px;
        padding:4px 11px;cursor:pointer;font-size:.78rem;white-space:nowrap}}
button:hover{{background:#2ea043}}
button.gray{{background:#21262d}} button.gray:hover{{background:#30363d}}
button.sel{{outline:2px solid var(--hub)}}
input[type=range]{{width:85px;accent-color:var(--hub);cursor:pointer}}
.lbl{{font-size:.75rem;color:#8b949e}}
.val{{font-size:.82rem;color:var(--hub);min-width:36px}}
#time-disp{{font-size:.88rem;color:var(--mon);font-weight:700;min-width:100px}}

#legend{{padding:4px 12px;background:#0d1117;border-bottom:1px solid var(--border);
         display:flex;gap:10px;flex-wrap:wrap;flex-shrink:0}}
.leg{{display:flex;align-items:center;gap:4px;font-size:.72rem;color:#8b949e}}
.dot{{width:8px;height:8px;border-radius:50%}}
.ln{{width:18px;height:3px;border-radius:1px}}

#charts{{flex:1;padding:5px 8px;display:flex;flex-direction:column;gap:5px;min-height:0}}
.cw{{flex:1;display:flex;flex-direction:column;min-height:0}}
.ct{{font-size:.72rem;color:var(--hub);padding:1px 0;flex-shrink:0}}
.cc{{flex:1;width:100%!important;display:block}}

#statbar{{background:var(--panel);border-top:1px solid var(--border);
          padding:4px 12px;display:flex;gap:14px;flex-wrap:wrap;flex-shrink:0}}
.st{{display:flex;gap:3px;font-size:.75rem}}
.sk{{color:#8b949e}}.sv{{font-weight:700}}
</style>
</head>
<body>
<header>
  <h1>CLoTH-Gossip シミュレーション可視化</h1>
  <span class="sub">seed7 / n=12800 / hold攻撃 / amt=100 / p=0.001 ｜ 全{len(degree)}ノード・全取引・全期間</span>
</header>
<div class="main">
  <div id="left">
    <div id="net-wrap"><canvas id="net-canvas"></canvas></div>
    <div id="tl-wrap">
      <div id="tl-outer">
        <div id="tl-fill"></div>
        <div id="tl-cur"></div>
      </div>
    </div>
  </div>
  <div id="right">
    <div id="ctrl">
      <div class="row">
        <button id="btn-play">▶ 再生</button>
        <span class="lbl">速度</span>
        <input type="range" id="spd" min="10" max="5000" step="10" value="500">
        <span class="val" id="spd-lbl">500×</span>
        <span id="time-disp">0 s / {DURATION//1000} s</span>
        <button class="gray" id="btn-reset">↺ リセット</button>
      </div>
      <div class="row">
        <span class="lbl">条件:</span>
        <button id="btn-nd" class="sel" onclick="setCond('nd')">従来（防御なし）</button>
        <button id="btn-m2" class="gray" onclick="setCond('m2')">提案（method2）</button>
      </div>
    </div>
    <div id="legend">
      <div class="leg"><span class="dot" style="background:#58a6ff"></span>ハブ</div>
      <div class="leg"><span class="dot" style="background:#f85149"></span>攻撃者</div>
      <div class="leg"><span class="dot" style="background:#3fb950"></span>監視者</div>
      <div class="leg"><span class="dot" style="background:#6e7681"></span>通常ノード</div>
      <div class="leg"><span class="ln" style="background:#ff7b72"></span>hold中HTLC経路</div>
      <div class="leg"><span class="ln" style="background:#79c0ff"></span>通常決済経路(従来)</div>
      <div class="leg"><span class="ln" style="background:#56d364"></span>通常決済経路(提案)</div>
    </div>
    <div id="charts">
      <div class="cw">
        <div class="ct">① 同時進行HTLC数 （橙=hold攻撃中 / グレー=通常）</div>
        <canvas class="cc" id="ch-active"></canvas>
      </div>
      <div class="cw">
        <div class="ct">② 累積: 成功(緑) / 攻撃遅延あり(橙) / 失敗(赤)</div>
        <canvas class="cc" id="ch-cum"></canvas>
      </div>
    </div>
    <div id="statbar">
      <div class="st"><span class="sk">進行中:</span><span class="sv" id="s-ac">0</span></div>
      <div class="st"><span class="sk">hold中:</span><span class="sv" id="s-aa" style="color:#ff7b72">0</span></div>
      <div class="st"><span class="sk">累積成功:</span><span class="sv" id="s-ok" style="color:#3fb950">0</span></div>
      <div class="st"><span class="sk">攻撃遅延:</span><span class="sv" id="s-ad" style="color:#ff7b72">0</span></div>
      <div class="st"><span class="sk">失敗:</span><span class="sv" id="s-fc" style="color:#f85149">0</span></div>
      <div class="st"><span class="sk">完了:</span><span class="sv" id="s-prog">0/{len(nd_all)}</span></div>
    </div>
  </div>
</div>
<script>
const DATA = {data_json};
const DURATION = DATA.duration, BIN = DATA.bin_ms;

// ── ノード情報マップ [id, x, y, deg, kind] ────────────────────
const NODE_POS = {{}};   // id -> {{x,y,deg,kind}}
DATA.nodes.forEach(([id,x,y,deg,kind])=>NODE_POS[id]={{x,y,deg,kind}});
const MAL_IDS = new Set(DATA.mal_ids);
const MON_IDS = new Set(DATA.mon_ids);

// ── 状態 ──────────────────────────────────────────────────────
let cond="nd", playing=false, simTime=0, lastTs=null, speedMul=500;
const nc = document.getElementById("net-canvas");
const nctx = nc.getContext("2d");

// スケール（Python座標系 → Canvas座標系）
let scaleX=1, scaleY=1, offX=0, offY=0;
const REF_W={CANVAS_W}, REF_H={CANVAS_H};
function updateScale(){{
  scaleX = nc.width  / REF_W;
  scaleY = nc.height / REF_H;
  offX = 0; offY = 0;
}}
function px(x){{ return x * scaleX + offX; }}
function py(y){{ return y * scaleY + offY; }}

function getPmts(){{ return cond==="nd" ? DATA.nd_key : DATA.m2_key; }}
function getTS(){{   return cond==="nd" ? DATA.ts_nd  : DATA.ts_m2;  }}

// ── ユーティリティ ────────────────────────────────────────────
function posOnPath(hops, prog) {{
  const seg = hops.length - 1; if(seg < 1) return null;
  const fi = Math.min(Math.floor(prog * seg), seg - 1);
  const fp = (prog * seg) - fi;
  const a = NODE_POS[hops[fi]], b = NODE_POS[hops[fi+1]];
  if(!a || !b) return null;
  return {{
    x: px(a.x + (b.x-a.x)*fp),
    y: py(a.y + (b.y-a.y)*fp),
    si: fi, sp: fp
  }};
}}

function drawArrow(x1,y1,x2,y2,color,alpha){{
  const mx=(x1+x2)/2, my=(y1+y2)/2;
  const dx=x2-x1, dy=y2-y1, len=Math.sqrt(dx*dx+dy*dy);
  if(len<18) return;
  const ux=dx/len, uy=dy/len, s=5;
  nctx.beginPath();
  nctx.moveTo(mx+ux*s, my+uy*s);
  nctx.lineTo(mx-ux*s-uy*s*.6, my-uy*s+ux*s*.6);
  nctx.lineTo(mx-ux*s+uy*s*.6, my-uy*s-ux*s*.6);
  nctx.closePath();
  nctx.globalAlpha = alpha;
  nctx.fillStyle = color;
  nctx.fill();
  nctx.globalAlpha = 1;
}}

// ── ネットワーク描画 ──────────────────────────────────────────
function drawNet(t) {{
  if(!nc.width) return;
  const W=nc.width, H=nc.height;
  nctx.clearRect(0,0,W,H);

  // ─ 背景エッジ（上位ハブ間）
  nctx.lineWidth = 0.5;
  DATA.bg_edges.forEach(([fn,tn])=>{{
    const a=NODE_POS[fn], b=NODE_POS[tn]; if(!a||!b) return;
    nctx.beginPath();
    nctx.moveTo(px(a.x), py(a.y));
    nctx.lineTo(px(b.x), py(b.y));
    nctx.strokeStyle = "rgba(80,120,180,0.12)";
    nctx.stroke();
  }});

  // ─ 全ノードを小さい点で描画
  // kind: 0=normal, 1=hub, 2=malicious, 3=monitor
  const KIND_COL = ["#3d4450","#58a6ff","#f85149","#3fb950"];
  const KIND_R   = [1.2, 2.5, 2.0, 2.2];

  DATA.nodes.forEach(([id,x,y,deg,kind])=>{{
    const r = kind===0
      ? (deg>10 ? 1.8 : 1.2)
      : KIND_R[kind] + Math.log2(deg+1)*0.3;
    nctx.beginPath();
    nctx.arc(px(x), py(y), r, 0, Math.PI*2);
    nctx.fillStyle = KIND_COL[kind];
    nctx.fill();
  }});

  // ─ アクティブ取引パスを描画
  const pmts = getPmts();
  const allActive = pmts.filter(p => p.st <= t && t < p.et && p.hops.length >= 2);
  const atkActive  = allActive.filter(p=>p.atk).slice(0, 25);
  const normActive = allActive.filter(p=>!p.atk).slice(0, 20);
  const active = [...atkActive, ...normActive];

  active.forEach(p => {{
    const hops = p.hops.filter(h => NODE_POS[h]);
    if(hops.length < 2) return;
    const dur = Math.max(500, p.et - p.st);
    const rawProg = Math.max(0, Math.min(1, (t - p.st) / dur));

    // hold: 最初の悪意ノードで停止
    let holdAt = null;
    if(p.atk) {{
      const mi = hops.findIndex(h => MAL_IDS.has(h));
      if(mi >= 0) holdAt = {{ node: hops[mi], frac: mi / (hops.length-1) }};
    }}
    const prog = holdAt ? Math.min(rawProg, holdAt.frac) : rawProg;

    const isM2 = cond === "m2";
    const passCol  = p.atk ? "rgba(255,100,70,0.9)"
                   : isM2  ? "rgba(86,211,100,0.85)" : "rgba(100,165,255,0.85)";
    const futureCol= p.atk ? "rgba(255,100,70,0.18)"
                   : isM2  ? "rgba(86,211,100,0.15)" : "rgba(100,165,255,0.15)";
    const arrowCol = p.atk ? "#ff6040" : isM2 ? "#56d364" : "#79c0ff";

    // パスを描く
    const segN = hops.length - 1;
    const curSeg = prog * segN;
    const curIdx = Math.min(Math.floor(curSeg), segN-1);
    const curFrac = curSeg - curIdx;

    for(let i=0; i<segN; i++) {{
      const na = NODE_POS[hops[i]], nb = NODE_POS[hops[i+1]];
      if(!na||!nb) continue;
      const ax=px(na.x), ay=py(na.y), bx=px(nb.x), by=py(nb.y);
      if(i < curIdx) {{
        nctx.beginPath(); nctx.moveTo(ax,ay); nctx.lineTo(bx,by);
        nctx.strokeStyle=passCol; nctx.lineWidth=2.2;
        nctx.globalAlpha=0.88; nctx.stroke(); nctx.globalAlpha=1;
        drawArrow(ax,ay,bx,by,arrowCol,0.85);
      }} else if(i === curIdx) {{
        const mx = ax+(bx-ax)*curFrac, my2 = ay+(by-ay)*curFrac;
        nctx.beginPath(); nctx.moveTo(ax,ay); nctx.lineTo(mx,my2);
        nctx.strokeStyle=passCol; nctx.lineWidth=2.2;
        nctx.globalAlpha=0.88; nctx.stroke(); nctx.globalAlpha=1;
        nctx.setLineDash([4,5]);
        nctx.beginPath(); nctx.moveTo(mx,my2); nctx.lineTo(bx,by);
        nctx.strokeStyle=futureCol; nctx.lineWidth=1.2;
        nctx.globalAlpha=0.5; nctx.stroke();
        nctx.setLineDash([]); nctx.globalAlpha=1;
        drawArrow(ax,ay,bx,by,arrowCol,0.4);
      }} else {{
        nctx.setLineDash([3,6]);
        nctx.beginPath(); nctx.moveTo(ax,ay); nctx.lineTo(bx,by);
        nctx.strokeStyle=futureCol; nctx.lineWidth=1.0;
        nctx.globalAlpha=0.4; nctx.stroke();
        nctx.setLineDash([]); nctx.globalAlpha=1;
      }}
    }}

    // 先頭ドット
    const headPos = posOnPath(hops, prog);
    if(!headPos) return;
    const hx=headPos.x, hy=headPos.y;

    if(holdAt && prog >= holdAt.frac - 0.01) {{
      // HOLD: パルスリング
      const phase = (t/300) % 1;
      const pulse = Math.sin(phase*Math.PI*2)*0.5+0.5;
      [14+pulse*7, 9+pulse*4].forEach((rr,ri)=>{{
        nctx.beginPath(); nctx.arc(hx,hy,rr,0,Math.PI*2);
        nctx.strokeStyle=`rgba(255,80,60,${{0.55-ri*.18}})`;
        nctx.lineWidth=1.8-ri*.4; nctx.stroke();
      }});
      nctx.fillStyle="rgba(255,120,80,.95)";
      nctx.font="bold 8px sans-serif";
      nctx.textAlign="center"; nctx.textBaseline="bottom";
      nctx.fillText("HOLD", hx, hy-16);
      nctx.beginPath(); nctx.arc(hx,hy,5,0,Math.PI*2);
      nctx.fillStyle="#ff5050"; nctx.fill();
    }} else {{
      // 彗星エフェクト
      for(let ti=5;ti>=0;ti--){{
        const tp=Math.max(0, prog - ti*0.018);
        const tPos=posOnPath(hops,tp); if(!tPos) continue;
        const a=(5-ti)/5;
        nctx.beginPath(); nctx.arc(tPos.x,tPos.y,4*(1-ti/5*.55),0,Math.PI*2);
        nctx.fillStyle=p.atk?`rgba(255,100,70,${{a*.7}})`
          :(isM2?`rgba(86,211,100,${{a*.7}})`:`rgba(120,185,255,${{a*.7}})`);
        nctx.fill();
      }}
      nctx.beginPath(); nctx.arc(hx,hy,4,0,Math.PI*2);
      nctx.fillStyle=p.atk?"#ff7050":(isM2?"#56d364":"#90c8ff"); nctx.fill();
      nctx.beginPath(); nctx.arc(hx,hy,1.8,0,Math.PI*2);
      nctx.fillStyle="rgba(255,255,255,.9)"; nctx.fill();
    }}
  }});

  // ─ ラベル付きノードを最前面に再描画
  const nodeTraffic = {{}};
  active.forEach(p=>p.hops.forEach(h=>nodeTraffic[h]=(nodeTraffic[h]||0)+1));

  DATA.label_nodes.forEach(n=>{{
    const np = NODE_POS[n.id]; if(!np) return;
    const x=px(np.x), y=py(np.y);
    const r = 6 + Math.log2(n.deg+1)*1.1;
    const traffic = nodeTraffic[n.id]||0;
    const col = n.kind===1?"#58a6ff":n.kind===2?"#f85149":"#3fb950";

    // グロー
    if(traffic > 0){{
      const gr = nctx.createRadialGradient(x,y,r,x,y,r+5+traffic*2);
      const gc = n.kind===2?"255,81,73":n.kind===3?"63,185,80":"88,166,255";
      gr.addColorStop(0,`rgba(${{gc}},0.45)`);
      gr.addColorStop(1,`rgba(${{gc}},0)`);
      nctx.beginPath(); nctx.arc(x,y,r+5+traffic*2,0,Math.PI*2);
      nctx.fillStyle=gr; nctx.fill();
    }}

    nctx.beginPath(); nctx.arc(x,y,r,0,Math.PI*2);
    nctx.fillStyle=col; nctx.fill();
    nctx.strokeStyle=traffic>0?"rgba(255,255,255,.5)":"rgba(255,255,255,.12)";
    nctx.lineWidth=traffic>0?1.5:0.8; nctx.stroke();

    // IDラベル
    const lc=n.kind===2?"#ffb3ae":n.kind===3?"#7ee787":"#a5d6ff";
    nctx.fillStyle=lc;
    nctx.font=`bold ${{Math.max(8,Math.min(11,r-1))}}px sans-serif`;
    nctx.textAlign="center"; nctx.textBaseline="top";
    nctx.fillText("n"+n.id, x, y+r+2);
    if(n.kind===2 && traffic>0){{
      nctx.font="bold 8px sans-serif"; nctx.fillStyle="rgba(255,150,120,.9)";
      nctx.fillText("⚠攻撃者", x, y-r-12);
    }}
  }});
}}

// ── チャート描画 ───────────────────────────────────────────────
function drawChart(cid, series, t, keys, colors, labels) {{
  const cv=document.getElementById(cid);
  const ctx=cv.getContext("2d");
  const W=cv.width, H=cv.height;
  ctx.clearRect(0,0,W,H);
  const pad={{l:38,r:8,t:5,b:18}};
  const cw=W-pad.l-pad.r, ch=H-pad.t-pad.b;
  if(!series||!series.length) return;
  const tBin=Math.floor(t/BIN);
  ctx.strokeStyle="rgba(255,255,255,0.05)"; ctx.lineWidth=1;
  for(let i=0;i<=4;i++){{
    const y=pad.t+ch*(1-i/4);
    ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(pad.l+cw,y); ctx.stroke();
  }}
  const maxV=Math.max(1,...series.flatMap(s=>keys.map(k=>s[k]||0)));
  const xS=t2=>pad.l+(t2/DURATION)*cw;
  const yS=v=>pad.t+ch*(1-v/maxV);
  keys.forEach((key,ki)=>{{
    ctx.beginPath(); let first=true;
    series.forEach((s,si)=>{{
      if(si>tBin) return;
      const x=xS(s.t), y=yS(s[key]||0);
      first ? (ctx.moveTo(x,y),first=false) : ctx.lineTo(x,y);
    }});
    ctx.strokeStyle=colors[ki]; ctx.lineWidth=1.8; ctx.stroke();
    ctx.fillStyle=colors[ki]; ctx.font="8px sans-serif"; ctx.textAlign="left";
    ctx.fillText(labels[ki], pad.l+4+ki*65, pad.t+9);
  }});
  const cx2=xS(Math.min(t,DURATION));
  ctx.beginPath(); ctx.moveTo(cx2,pad.t); ctx.lineTo(cx2,pad.t+ch);
  ctx.strokeStyle="rgba(63,185,80,.7)"; ctx.lineWidth=1.5; ctx.stroke();
  ctx.fillStyle="#4a5568"; ctx.font="8px sans-serif"; ctx.textAlign="right";
  [0,.5,1].forEach(f=>ctx.fillText(Math.round(maxV*f),pad.l-3,pad.t+ch*(1-f)+3));
  ctx.textAlign="center"; ctx.fillStyle="#4a5568";
  [0,.25,.5,.75,1].forEach(f=>{{
    const s=Math.round(DURATION/1000*f);
    ctx.fillText(`${{Math.floor(s/60)}}m${{s%60}}s`, pad.l+cw*f, pad.t+ch+13);
  }});
}}

// ── ステータス更新 ─────────────────────────────────────────────
function updateStatus(t) {{
  const bi=Math.min(Math.floor(t/BIN),getTS().length-1);
  const s=getTS()[bi]||{{}};
  document.getElementById("s-ac").textContent=(s.an||0)+(s.aa||0);
  document.getElementById("s-aa").textContent=s.aa||0;
  document.getElementById("s-ok").textContent=s.ok||0;
  document.getElementById("s-ad").textContent=s.ac||0;
  document.getElementById("s-fc").textContent=s.fc||0;
  document.getElementById("s-prog").textContent=`${{s.ok||0}}/${{DATA.n_total}}`;
  document.getElementById("time-disp").textContent=
    `${{(t/1000).toFixed(0)}} s / ${{(DURATION/1000).toFixed(0)}} s`;
  const pct=Math.min(t/DURATION,1)*100;
  document.getElementById("tl-cur").style.left=pct+"%";
  document.getElementById("tl-fill").style.width=pct+"%";
}}

// ── メインループ ───────────────────────────────────────────────
function frame(ts) {{
  if(!playing) return;
  if(lastTs!==null) simTime=Math.min(simTime+(ts-lastTs)*speedMul,DURATION);
  lastTs=ts;
  drawNet(simTime);
  drawChart("ch-active",getTS(),simTime,["aa","an"],["#ff7b72","#4a5568"],["hold中","通常"]);
  drawChart("ch-cum",   getTS(),simTime,["ok","ac","fc"],["#3fb950","#ff7b72","#f85149"],["成功","攻撃遅延","失敗"]);
  updateStatus(simTime);
  if(simTime>=DURATION){{playing=false;document.getElementById("btn-play").textContent="▶ 再生";return;}}
  requestAnimationFrame(frame);
}}

// ── リサイズ ───────────────────────────────────────────────────
function resizeAll() {{
  nc.width=nc.offsetWidth; nc.height=nc.offsetHeight; updateScale();
  ["ch-active","ch-cum"].forEach(id=>{{
    const c=document.getElementById(id); c.width=c.offsetWidth; c.height=c.offsetHeight;
  }});
}}
function redraw() {{
  drawNet(simTime);
  drawChart("ch-active",getTS(),simTime,["aa","an"],["#ff7b72","#4a5568"],["hold中","通常"]);
  drawChart("ch-cum",   getTS(),simTime,["ok","ac","fc"],["#3fb950","#ff7b72","#f85149"],["成功","攻撃遅延","失敗"]);
  updateStatus(simTime);
}}

// ── UI ─────────────────────────────────────────────────────────
document.getElementById("btn-play").addEventListener("click",()=>{{
  playing=!playing;
  document.getElementById("btn-play").textContent=playing?"⏸ 一時停止":"▶ 再生";
  if(playing){{lastTs=null;requestAnimationFrame(frame);}}
}});
document.getElementById("btn-reset").addEventListener("click",()=>{{
  simTime=0;playing=false;lastTs=null;
  document.getElementById("btn-play").textContent="▶ 再生";
  redraw();
}});
document.getElementById("spd").addEventListener("input",e=>{{
  speedMul=+e.target.value;
  document.getElementById("spd-lbl").textContent=speedMul+"×";
}});
document.getElementById("tl-outer").addEventListener("click",e=>{{
  const b=e.currentTarget.getBoundingClientRect();
  simTime=(e.clientX-b.left)/b.width*DURATION;
  redraw();
}});
function setCond(c) {{
  cond=c;
  document.getElementById("btn-nd").className=c==="nd"?"sel":"gray";
  document.getElementById("btn-m2").className=c==="m2"?"sel":"gray";
  redraw();
}}
window.setCond=setCond;

const ro=new ResizeObserver(()=>{{resizeAll();redraw();}});
ro.observe(document.getElementById("net-wrap"));
ro.observe(document.getElementById("right"));
window.addEventListener("load",()=>{{resizeAll();redraw();}});
</script>
</body>
</html>"""

with open(OUT, "w") as f:
    f.write(html)
print(f"saved: {OUT}  ({os.path.getsize(OUT)/1024:.0f} KB)")
