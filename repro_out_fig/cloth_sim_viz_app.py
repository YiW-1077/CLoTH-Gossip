#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLoTH-Gossip シミュレーション可視化アプリ（Streamlit + Canvas埋め込み）
使い方: streamlit run cloth_sim_viz_app.py

・任意の結果ディレクトリを読み込み（単一条件）
・取引件数は制限なし（hops付きを最大3000件サンプリングして描画）
・アニメーション/速度/シークは全てブラウザ内JS完結（Streamlit再実行なし=チラつきなし）
・速度スライダー: 1×（毎秒1件）〜5000×
"""
import streamlit as st
import streamlit.components.v1 as components
import csv, json, math, os
from collections import Counter, defaultdict

st.set_page_config(page_title="CLoTH-Gossip 可視化", layout="wide",
                   initial_sidebar_state="expanded")
st.markdown("""
<style>
.block-container{padding-top:0.5rem;padding-bottom:0.3rem;max-width:100%}
[data-testid="stMetricValue"]{font-size:1rem!important}
</style>""", unsafe_allow_html=True)

PHI = (1 + 5**0.5) / 2
CANVAS_W, CANVAS_H = 900, 700
# 経路描画は hops付きの全支払いを対象にする（サンプリングなし）

# ── 黄金角同心円レイアウト ─────────────────────────────────────
def golden_layout(degree):
    cx, cy = CANVAS_W / 2, CANVAS_H / 2
    max_r  = min(CANVAS_W, CANVAS_H) * 0.46
    nodes  = sorted(degree.keys(), key=lambda n: -degree[n])
    N      = len(nodes)
    pos = {}
    for rank, nid in enumerate(nodes):
        norm  = rank / (N - 1) if N > 1 else 0
        r     = max_r * (norm ** 0.45)
        angle = rank * 2 * math.pi / (PHI * PHI)
        pos[nid] = (cx + math.cos(angle) * r, cy + math.sin(angle) * r)
    return pos

# ── 評判ファイルの自動探索 ───────────────────────────────────────
# no_defense条件には reputation_dynamics.csv が存在しない（監視無効のため）。
# 攻撃者ノードはトポロジ（シード）共通なので、同一runツリー配下の
# method2の reputation_dynamics.csv を自動発見して流用する。
def find_reputation(results_dir: str, override: str = ""):
    if override and os.path.exists(override):
        return override
    direct = f"{results_dir}/reputation_dynamics.csv"
    if os.path.exists(direct):
        return direct
    # 上位ディレクトリを辿ってrunルート（basenameが数字列=タイムスタンプ）を探す
    cur, root = os.path.abspath(results_dir), None
    for _ in range(8):
        parent = os.path.dirname(cur)
        if parent == cur: break
        base = os.path.basename(cur)
        if base.isdigit() and len(base) >= 8:
            root = cur; break
        cur = parent
    search_root = root or os.path.dirname(os.path.abspath(results_dir))
    for dp, _dns, fns in os.walk(search_root):
        if "reputation_dynamics.csv" in fns:
            return os.path.join(dp, "reputation_dynamics.csv")
    return None

# ── データ読み込み ────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def load_data(results_dir: str, rep_override: str = "", _progress=None):
    # _progress は先頭が "_" なのでStreamlitのキャッシュキーに含まれない
    def report(frac, text):
        if _progress: _progress(frac, text)

    edg_path = f"{results_dir}/edges_output.csv"
    pay_path = f"{results_dir}/payments_output.csv"
    for p in (edg_path, pay_path):
        if not os.path.exists(p):
            return None, f"ファイルが見つかりません: {p}"

    report(0.03, "評判ファイル探索中...")
    rep_path = find_reputation(results_dir, rep_override)
    mal_set, mon_set = set(), set()
    if rep_path:
        with open(rep_path) as f:
            for r in csv.DictReader(f):
                if r.get("is_malicious", "0") == "1": mal_set.add(int(r["node_id"]))
                if r.get("is_monitor",  "0") == "1": mon_set.add(int(r["node_id"]))

    report(0.08, "エッジ読み込み中...")
    degree = Counter()
    adj    = defaultdict(set)
    with open(edg_path) as f:
        for r in csv.DictReader(f):
            fn, tn = int(r["from_node_id"]), int(r["to_node_id"])
            degree[fn] += 1; degree[tn] += 1
            adj[fn].add(tn); adj[tn].add(fn)

    report(0.20, "ノード座標を計算中...")
    node_pos = golden_layout(degree)
    top_hubs = [n for n, _ in degree.most_common(20) if n not in mal_set][:12]
    mal_hubs = sorted(mal_set, key=lambda n: -degree[n])[:10]
    top50    = {n for n, _ in degree.most_common(50)}

    seen_pairs, bg_edges = set(), []
    for fn in top50:
        for tn in adj[fn]:
            if tn in top50:
                pair = (min(fn, tn), max(fn, tn))
                if pair not in seen_pairs:
                    bg_edges.append((fn, tn)); seen_pairs.add(pair)

    report(0.28, "支払いを読み込み中...")
    payments = []
    n_read = 0
    with open(pay_path) as f:
        for r in csv.DictReader(f):
            if r.get("is_warmup", "0") not in ("0", "0.0", ""): continue
            st_ms  = int(r["start_time"])
            et_raw = r.get("end_time", "-1")
            et_ms  = int(et_raw) if et_raw not in ("", "-1") else st_ms + 120000
            ok  = r["is_success"] == "1"
            atk = int(r.get("attack_delay_events", "0")) > 0
            hops = []
            try:
                hist = json.loads(r.get("attempts_history", "[]"))
                if hist:
                    seen_h = set()
                    for hop in hist[-1].get("route", []):
                        for k in ("from_node_id", "to_node_id"):
                            v = hop.get(k)
                            if v is not None:
                                nid = int(v)
                                if nid not in seen_h: hops.append(nid); seen_h.add(nid)
            except: pass
            payments.append({"st": st_ms, "et": et_ms, "ok": ok, "atk": atk, "hops": hops})
            n_read += 1
            if n_read % 2000 == 0:
                report(min(0.28 + 0.45 * n_read / 13000, 0.72),
                       f"支払いを読み込み中... {n_read:,}件")

    if not payments:
        return None, "ウォームアップ後の決済が0件です"

    report(0.74, "時刻の正規化中...")
    T0       = min(p["st"] for p in payments)
    T_END    = max(p["et"] for p in payments)
    DURATION = T_END - T0
    for p in payments:
        p["st"] -= T0
        p["et"]  = min(p["et"] - T0, p["st"] + 60000)

    # 全支払い（hops付き）を描画対象にする（サンプリングしない）
    report(0.80, "描画対象を整列中...")
    key_pmts = sorted([p for p in payments if p["hops"]], key=lambda p: p["st"])

    # ── 時系列集計（差分配列で O(取引数+ビン数) に高速化）─────────────
    report(0.86, "時系列を集計中...")
    BIN = 10000
    nbins = DURATION // BIN + 1
    diff_an = [0] * (nbins + 2); diff_aa = [0] * (nbins + 2)
    c_ok = [0] * (nbins + 2); c_ac = [0] * (nbins + 2); c_fc = [0] * (nbins + 2)
    for p in payments:
        st_, et_, atk_, ok_ = p["st"], p["et"], p["atk"], p["ok"]
        # active（bの開始時刻 b*BIN が [st,et) に入るbの範囲）
        b_lo = (st_ + BIN - 1) // BIN
        if b_lo < 0: b_lo = 0
        b_hi = (et_ - 1) // BIN
        if b_hi >= b_lo:
            d = diff_aa if atk_ else diff_an
            d[b_lo] += 1
            if b_hi + 1 <= nbins: d[b_hi + 1] -= 1
        # 完了bin（(b+1)*BIN >= et となる最小のb）から累積
        bc = (et_ + BIN - 1) // BIN - 1
        if bc < 0: bc = 0
        if bc > nbins: bc = nbins
        if ok_:
            c_ok[bc] += 1
            if atk_: c_ac[bc] += 1
        else:
            c_fc[bc] += 1
    ts = []
    run_an = run_aa = cum_ok = cum_ac = cum_fc = 0
    for b in range(nbins):
        run_an += diff_an[b]; run_aa += diff_aa[b]
        cum_ok += c_ok[b];   cum_ac += c_ac[b];   cum_fc += c_fc[b]
        ts.append({"t": b * BIN, "an": run_an, "aa": run_aa,
                   "ok": cum_ok, "ac": cum_ac, "fc": cum_fc})
    report(0.92, "集計完了")

    return {
        "degree": degree, "node_pos": node_pos, "N_nodes": len(degree),
        "mal_set": mal_set, "mon_set": mon_set,
        "top_hubs": top_hubs, "mal_hubs": mal_hubs,
        "label_nodes": set(top_hubs) | set(mal_hubs) | mon_set,
        "bg_edges": bg_edges, "key_pmts": key_pmts,
        "ts": ts, "DURATION": DURATION, "BIN": BIN,
        "n_total": len(payments), "n_disp": len(key_pmts),
        "label": os.path.basename(results_dir),
        "rep_path": rep_path,
    }, None

# ── JS用JSONペイロード構築 ────────────────────────────────────────
@st.cache_data(show_spinner=False)
def build_payload(results_dir: str, rep_override: str = "", _progress=None):
    # load_dataの進度(0-0.92)を全体の0-0.90にマップ
    data, err = load_data(
        results_dir, rep_override,
        _progress=(lambda f, t: _progress(f * 0.98, t)) if _progress else None)
    if err:
        return None, None, err

    def report(frac, text):
        if _progress: _progress(frac, text)

    mal_set  = data["mal_set"]
    mon_set  = data["mon_set"]
    hub_set  = set(data["top_hubs"])
    def kind(nid):
        if nid in mon_set: return 3
        if nid in mal_set: return 2
        if nid in hub_set: return 1
        return 0
    node_pos = data["node_pos"]
    degree   = data["degree"]

    report(0.94, "ノードデータ構築中...")
    nodes_compact = []
    for nid, (x, y) in node_pos.items():
        nodes_compact.append([nid, round(x, 1), round(y, 1), degree[nid], kind(nid)])

    label_nodes = []
    for nid in data["label_nodes"]:
        if nid not in node_pos: continue
        x, y = node_pos[nid]
        label_nodes.append({"id": nid, "x": round(x, 1), "y": round(y, 1),
                            "deg": degree[nid], "kind": kind(nid)})

    # id は未使用のため省略。ok は復路の色分け(成功=緑/失敗=赤)に使うため保持
    report(0.97, "経路データ構築中...")
    key = [{"st": p["st"], "et": p["et"], "atk": 1 if p["atk"] else 0,
            "ok": 1 if p["ok"] else 0, "hops": p["hops"]} for p in data["key_pmts"]]

    payload = {
        "nodes": nodes_compact,
        "label_nodes": label_nodes,
        "bg_edges": [[fn, tn] for (fn, tn) in data["bg_edges"]],
        "key": key,
        "ts": data["ts"],
        "duration": data["DURATION"],
        "bin_ms": data["BIN"],
        "n_total": data["n_total"],
        "n_disp": data["n_disp"],
        "mal_ids": list(data["mal_set"]),
        "mon_ids": list(data["mon_set"]),
        "label": data["label"],
    }
    meta = {
        "N_nodes": data["N_nodes"], "n_total": data["n_total"],
        "n_disp": data["n_disp"], "DURATION": data["DURATION"],
        "label": data["label"],
        "ts_last": data["ts"][-1] if data["ts"] else {},
        "rep_path": data["rep_path"],
        "n_mal": len(data["mal_set"]), "n_mon": len(data["mon_set"]),
    }
    return json.dumps(payload, ensure_ascii=False), meta, None

# ── Canvas HTML/JS テンプレート（プレースホルダ __DATA_JSON__ ）──
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="ja">
<head><meta charset="utf-8">
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--hub:#58a6ff;--mal:#f85149;--mon:#3fb950;}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg);color:#e6edf3;
  font-family:"Hiragino Sans","Helvetica Neue",sans-serif;font-size:13px;overflow:hidden}
.wrap{display:flex;height:100%;width:100%}
#left{flex:0 0 63%;display:flex;flex-direction:column;border-right:1px solid var(--border)}
#net-wrap{flex:1;position:relative;overflow:hidden;min-height:0}
#net-canvas{position:absolute;inset:0;width:100%;height:100%}
#tl-wrap{padding:5px 10px;background:#0d1117;border-top:1px solid var(--border);flex-shrink:0}
#tl-outer{width:100%;height:14px;background:#21262d;border-radius:3px;position:relative;cursor:pointer;overflow:hidden}
#tl-fill{position:absolute;inset:0 auto 0 0;background:rgba(88,166,255,.22);pointer-events:none}
#tl-cur{position:absolute;top:0;bottom:0;width:2px;background:#3fb950;pointer-events:none}
#right{flex:1;display:flex;flex-direction:column;overflow:hidden}
#ctrl{padding:8px 12px;background:var(--panel);border-bottom:1px solid var(--border);flex-shrink:0}
.row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.row:last-child{margin-bottom:0}
button{background:#238636;color:#fff;border:none;border-radius:4px;padding:5px 13px;cursor:pointer;font-size:.82rem}
button:hover{background:#2ea043}
button.gray{background:#21262d}button.gray:hover{background:#30363d}
input[type=range]{flex:1;min-width:120px;accent-color:var(--hub);cursor:pointer}
.lbl{font-size:.75rem;color:#8b949e}
#spd-lbl{font-size:.85rem;color:var(--hub);font-weight:700;min-width:120px;text-align:right}
#time-disp{font-size:.9rem;color:var(--mon);font-weight:700}
#legend{padding:5px 12px;background:#0d1117;border-bottom:1px solid var(--border);display:flex;gap:11px;flex-wrap:wrap;flex-shrink:0}
.leg{display:flex;align-items:center;gap:4px;font-size:.72rem;color:#8b949e}
.dot{width:8px;height:8px;border-radius:50%}
.ln{width:16px;height:3px;border-radius:1px}
#charts{flex:1;padding:5px 8px;display:flex;flex-direction:column;gap:6px;min-height:0}
.cw{flex:1;display:flex;flex-direction:column;min-height:0}
.ct{font-size:.72rem;color:var(--hub);padding:1px 0;flex-shrink:0}
.cc{flex:1;width:100%!important;display:block}
#statbar{background:var(--panel);border-top:1px solid var(--border);padding:5px 12px;display:flex;gap:14px;flex-wrap:wrap;flex-shrink:0}
.st{display:flex;gap:3px;font-size:.75rem}
.sk{color:#8b949e}.sv{font-weight:700}
</style></head>
<body>
<div class="wrap">
  <div id="left">
    <div id="net-wrap"><canvas id="net-canvas"></canvas></div>
    <div id="tl-wrap"><div id="tl-outer"><div id="tl-fill"></div><div id="tl-cur"></div></div></div>
  </div>
  <div id="right">
    <div id="ctrl">
      <div class="row">
        <button id="btn-play">▶ 再生</button>
        <button class="gray" id="btn-reset">↺ リセット</button>
        <span id="time-disp">0 s / 0 s</span>
      </div>
      <div class="row">
        <span class="lbl">速度</span>
        <input type="range" id="spd" min="1" max="5000" step="1" value="1">
        <span id="spd-lbl">1×（毎秒1件）</span>
      </div>
    </div>
    <div id="legend">
      <div class="leg"><span class="dot" style="background:#58a6ff"></span>ハブ</div>
      <div class="leg"><span class="dot" style="background:#f85149"></span>攻撃者</div>
      <div class="leg"><span class="dot" style="background:#3fb950"></span>監視者</div>
      <div class="leg"><span class="dot" style="background:#6e7681"></span>通常</div>
      <div class="leg"><span class="ln" style="background:#79c0ff"></span>①送金(行き)</div>
      <div class="leg"><span class="ln" style="background:#56d364"></span>②決済確定(帰り)</div>
      <div class="leg"><span class="ln" style="background:#f85149"></span>②失敗通知(帰り)</div>
      <div class="leg"><span class="ln" style="background:#ff7b72"></span>hold攻撃(帰り無し)</div>
    </div>
    <div id="charts">
      <div class="cw"><div class="ct">① 同時進行HTLC数（橙=hold攻撃中 / グレー=通常）</div><canvas class="cc" id="ch-active"></canvas></div>
      <div class="cw"><div class="ct">② 累積: 成功(緑) / 攻撃遅延あり(橙) / 失敗(赤)</div><canvas class="cc" id="ch-cum"></canvas></div>
    </div>
    <div id="statbar">
      <div class="st"><span class="sk">進行中:</span><span class="sv" id="s-ac">0</span></div>
      <div class="st"><span class="sk">hold中:</span><span class="sv" id="s-aa" style="color:#ff7b72">0</span></div>
      <div class="st"><span class="sk">累積成功:</span><span class="sv" id="s-ok" style="color:#3fb950">0</span></div>
      <div class="st"><span class="sk">攻撃遅延:</span><span class="sv" id="s-ad" style="color:#ff7b72">0</span></div>
      <div class="st"><span class="sk">失敗:</span><span class="sv" id="s-fc" style="color:#f85149">0</span></div>
    </div>
  </div>
</div>
<script>
const DATA = __DATA_JSON__;
const DURATION = DATA.duration, BIN = DATA.bin_ms;
// 「毎秒1件」= 表示取引数(n_disp)ベースで校正（サンプリング後の見かけの件数に合わせる）
const N_DISP = Math.max(1, DATA.key.length);
const BASE_MUL = DURATION / (N_DISP * 1000);   // slider=1 → 表示取引を毎秒約1件

const NODE_POS = {};
DATA.nodes.forEach(([id,x,y,deg,kind])=>NODE_POS[id]={x,y,deg,kind});
const MAL_IDS = new Set(DATA.mal_ids);

let playing=false, simTime=0, lastTs=null, sliderVal=1;
const nc = document.getElementById("net-canvas");
const nctx = nc.getContext("2d");

let scale=1, offX=0, offY=0;
function updateScale(){
  scale = Math.min(nc.width/900, nc.height/700);
  offX = (nc.width  - 900*scale)/2;
  offY = (nc.height - 700*scale)/2;
}
function px(x){return offX + x*scale;}
function py(y){return offY + y*scale;}

function posOnPath(hops, prog){
  const seg = hops.length-1; if(seg<1) return null;
  const fi = Math.min(Math.floor(prog*seg), seg-1);
  const fp = (prog*seg)-fi;
  const a = NODE_POS[hops[fi]], b = NODE_POS[hops[fi+1]];
  if(!a||!b) return null;
  return {x:px(a.x+(b.x-a.x)*fp), y:py(a.y+(b.y-a.y)*fp)};
}
function drawArrow(x1,y1,x2,y2,color,alpha){
  const mx=(x1+x2)/2,my=(y1+y2)/2,dx=x2-x1,dy=y2-y1,len=Math.sqrt(dx*dx+dy*dy);
  if(len<18) return;
  const ux=dx/len,uy=dy/len,s=5;
  nctx.beginPath();
  nctx.moveTo(mx+ux*s,my+uy*s);
  nctx.lineTo(mx-ux*s-uy*s*.6,my-uy*s+ux*s*.6);
  nctx.lineTo(mx-ux*s+uy*s*.6,my-uy*s-ux*s*.6);
  nctx.closePath();
  nctx.globalAlpha=alpha; nctx.fillStyle=color; nctx.fill(); nctx.globalAlpha=1;
}

// ── 1脚（片道）を描画するヘルパー ────────────────────────────────
// hops: 進行方向に並んだノード列（往路=sender→receiver / 復路=その逆順）
// prog: この脚の進行度 0→1
// o: {pass,fut,arrow,cometRGB,dot} 色, label 先頭ラベル,
//    linesOnly=線のみ(ゴースト用), holdHead=先頭ドット省略(HOLD別描画用)
function drawLeg(hops, prog, o){
  const segN = hops.length-1; if(segN<1) return null;
  const curSeg=prog*segN, curIdx=Math.min(Math.floor(curSeg),segN-1), curFrac=curSeg-curIdx;
  for(let i=0;i<segN;i++){
    const na=NODE_POS[hops[i]],nb=NODE_POS[hops[i+1]]; if(!na||!nb) continue;
    const ax=px(na.x),ay=py(na.y),bx=px(nb.x),by=py(nb.y);
    if(i<curIdx){
      nctx.beginPath(); nctx.moveTo(ax,ay); nctx.lineTo(bx,by);
      nctx.strokeStyle=o.pass; nctx.lineWidth=o.linesOnly?1.4:2.2;
      nctx.globalAlpha=o.linesOnly?0.5:0.88; nctx.stroke(); nctx.globalAlpha=1;
      if(!o.linesOnly) drawArrow(ax,ay,bx,by,o.arrow,0.85);
    }else if(i===curIdx){
      const mx=ax+(bx-ax)*curFrac,my=ay+(by-ay)*curFrac;
      nctx.beginPath(); nctx.moveTo(ax,ay); nctx.lineTo(mx,my);
      nctx.strokeStyle=o.pass; nctx.lineWidth=o.linesOnly?1.4:2.2;
      nctx.globalAlpha=o.linesOnly?0.5:0.88; nctx.stroke(); nctx.globalAlpha=1;
      if(!o.linesOnly){
        nctx.setLineDash([4,5]);
        nctx.beginPath(); nctx.moveTo(mx,my); nctx.lineTo(bx,by);
        nctx.strokeStyle=o.fut; nctx.lineWidth=1.2; nctx.globalAlpha=0.5; nctx.stroke();
        nctx.setLineDash([]); nctx.globalAlpha=1;
        drawArrow(ax,ay,bx,by,o.arrow,0.4);
      }
    }else if(!o.linesOnly){
      nctx.setLineDash([3,6]);
      nctx.beginPath(); nctx.moveTo(ax,ay); nctx.lineTo(bx,by);
      nctx.strokeStyle=o.fut; nctx.lineWidth=1.0; nctx.globalAlpha=0.4; nctx.stroke();
      nctx.setLineDash([]); nctx.globalAlpha=1;
    }
  }
  const head=posOnPath(hops,prog); if(!head) return null;
  if(o.linesOnly) return head;
  // 彗星の尾
  for(let ti=5;ti>=0;ti--){
    const tp=Math.max(0,prog-ti*0.018), tPos=posOnPath(hops,tp); if(!tPos) continue;
    const a=(5-ti)/5;
    nctx.beginPath(); nctx.arc(tPos.x,tPos.y,4*(1-ti/5*.55),0,Math.PI*2);
    nctx.fillStyle="rgba("+o.cometRGB+","+(a*.7)+")"; nctx.fill();
  }
  if(o.holdHead) return head;   // 先頭はHOLD表示に譲る
  nctx.beginPath(); nctx.arc(head.x,head.y,4,0,Math.PI*2); nctx.fillStyle=o.dot; nctx.fill();
  nctx.beginPath(); nctx.arc(head.x,head.y,1.8,0,Math.PI*2); nctx.fillStyle="rgba(255,255,255,.9)"; nctx.fill();
  if(o.label){
    nctx.fillStyle=o.dot; nctx.font="bold 8px sans-serif";
    nctx.textAlign="center"; nctx.textBaseline="bottom"; nctx.fillText(o.label, head.x, head.y-9);
  }
  return head;
}

function drawNet(t){
  if(!nc.width) return;
  nctx.clearRect(0,0,nc.width,nc.height);

  // 背景エッジ
  nctx.lineWidth=0.6;
  DATA.bg_edges.forEach(([fn,tn])=>{
    const a=NODE_POS[fn],b=NODE_POS[tn]; if(!a||!b) return;
    nctx.beginPath(); nctx.moveTo(px(a.x),py(a.y)); nctx.lineTo(px(b.x),py(b.y));
    nctx.strokeStyle="rgba(80,120,180,0.12)"; nctx.stroke();
  });

  // 全ノード
  const KIND_COL=["#3d4450","#58a6ff","#f85149","#3fb950"];
  DATA.nodes.forEach(([id,x,y,deg,kind])=>{
    let r;
    if(kind===0) r = deg>10?1.8:1.2;
    else if(kind===1) r = 3+Math.log2(deg+1)*0.5;
    else if(kind===2) r = 2.5+Math.log2(deg+1)*0.35;
    else r = 3.5;
    nctx.beginPath(); nctx.arc(px(x),py(y),r,0,Math.PI*2);
    nctx.fillStyle=KIND_COL[kind]; nctx.fill();
  });

  // アクティブ取引経路
  const pmts = DATA.key;
  const allActive = pmts.filter(p=>p.st<=t && t<p.et && p.hops.length>=2);
  const atkA  = allActive.filter(p=>p.atk).slice(0,25);
  const nrmA  = allActive.filter(p=>!p.atk).slice(0,20);
  const active = [...atkA, ...nrmA];
  const nodeTraffic = {};

  active.forEach(p=>{
    const hops = p.hops.filter(h=>NODE_POS[h]);
    if(hops.length<2) return;
    hops.forEach(h=>nodeTraffic[h]=(nodeTraffic[h]||0)+1);
    const segN = hops.length-1;
    const dur  = Math.max(500, p.et-p.st);
    const rawProg = Math.max(0,Math.min(1,(t-p.st)/dur));

    // hold攻撃: 経路上の最初の悪意ノードで停止（往路のみ・決済確定=帰りは起きない）
    let holdFrac=null;
    if(p.atk){
      const mi = hops.findIndex(h=>MAL_IDS.has(h));
      if(mi>=0) holdFrac = mi/segN;
    }
    if(holdFrac!==null){
      const prog=Math.min(rawProg,holdFrac);
      drawLeg(hops, prog, {
        pass:"rgba(255,100,70,0.9)", fut:"rgba(255,100,70,0.18)",
        arrow:"#ff6040", cometRGB:"255,100,70", dot:"#ff7050", holdHead:true});
      const head=posOnPath(hops,prog);
      if(head){
        const phase=(t/300)%1, pulse=Math.sin(phase*Math.PI*2)*0.5+0.5;
        [14+pulse*7, 9+pulse*4].forEach((rr,ri)=>{
          nctx.beginPath(); nctx.arc(head.x,head.y,rr,0,Math.PI*2);
          nctx.strokeStyle="rgba(255,80,60,"+(0.55-ri*.18)+")"; nctx.lineWidth=1.8-ri*.4; nctx.stroke();
        });
        nctx.fillStyle="rgba(255,120,80,.95)"; nctx.font="bold 8px sans-serif";
        nctx.textAlign="center"; nctx.textBaseline="bottom"; nctx.fillText("HOLD",head.x,head.y-16);
        nctx.beginPath(); nctx.arc(head.x,head.y,5,0,Math.PI*2); nctx.fillStyle="#ff5050"; nctx.fill();
      }
      return;
    }

    // 通常決済: 前半=①送金(sender→receiver), 後半=②決済確定(receiver→sender逆順)
    const FWD_END=0.5;
    if(rawProg<=FWD_END){
      // 行き（HTLC設定が受信者へ伝播）
      drawLeg(hops, rawProg/FWD_END, {
        pass:"rgba(100,165,255,0.85)", fut:"rgba(100,165,255,0.18)",
        arrow:"#79c0ff", cometRGB:"120,185,255", dot:"#90c8ff", label:"①送金"});
    }else{
      // 行きの経路を薄い実線で残す（往復が一目で分かるように）
      drawLeg(hops, 1.0, {
        pass:"rgba(100,165,255,0.85)", fut:"rgba(100,165,255,0.1)",
        arrow:"#79c0ff", cometRGB:"120,185,255", dot:"#90c8ff", linesOnly:true});
      // 帰り（preimageで決済確定 or 失敗通知が送信者へ逆流）
      const ok=(p.ok===1);
      const rev=hops.slice().reverse();
      drawLeg(rev, (rawProg-FWD_END)/(1-FWD_END), {
        pass: ok?"rgba(86,211,100,0.9)":"rgba(248,81,73,0.9)",
        fut:  ok?"rgba(86,211,100,0.18)":"rgba(248,81,73,0.18)",
        arrow: ok?"#56d364":"#f85149",
        cometRGB: ok?"86,211,100":"248,81,73",
        dot: ok?"#56d364":"#f85149",
        label: ok?"②決済確定":"②失敗通知"});
    }
  });

  // ラベルノード（最前面）
  DATA.label_nodes.forEach(n=>{
    const x=px(n.x), y=py(n.y), r=6+Math.log2(n.deg+1)*1.1;
    const traffic=nodeTraffic[n.id]||0;
    const col=n.kind===1?"#58a6ff":n.kind===2?"#f85149":"#3fb950";
    if(traffic>0){
      const gc=n.kind===2?"255,81,73":n.kind===3?"63,185,80":"88,166,255";
      const gr=nctx.createRadialGradient(x,y,r,x,y,r+5+traffic*2);
      gr.addColorStop(0,"rgba("+gc+",0.45)"); gr.addColorStop(1,"rgba("+gc+",0)");
      nctx.beginPath(); nctx.arc(x,y,r+5+traffic*2,0,Math.PI*2); nctx.fillStyle=gr; nctx.fill();
    }
    nctx.beginPath(); nctx.arc(x,y,r,0,Math.PI*2); nctx.fillStyle=col; nctx.fill();
    nctx.strokeStyle=traffic>0?"rgba(255,255,255,.5)":"rgba(255,255,255,.12)";
    nctx.lineWidth=traffic>0?1.5:0.8; nctx.stroke();
    const lc=n.kind===2?"#ffb3ae":n.kind===3?"#7ee787":"#a5d6ff";
    nctx.fillStyle=lc; nctx.font="bold "+Math.max(8,Math.min(11,r-1))+"px sans-serif";
    nctx.textAlign="center"; nctx.textBaseline="top"; nctx.fillText("n"+n.id,x,y+r+2);
    if(n.kind===2 && traffic>0){
      nctx.font="bold 8px sans-serif"; nctx.fillStyle="rgba(255,150,120,.9)";
      nctx.fillText("⚠攻撃者",x,y-r-12);
    }
  });
}

function drawChart(cid, keys, colors, labels, t){
  const cv=document.getElementById(cid), ctx=cv.getContext("2d");
  const W=cv.width, H=cv.height; ctx.clearRect(0,0,W,H);
  const pad={l:38,r:8,t:5,b:18}, cw=W-pad.l-pad.r, ch=H-pad.t-pad.b;
  const series=DATA.ts; if(!series.length) return;
  const tBin=Math.floor(t/BIN);
  ctx.strokeStyle="rgba(255,255,255,0.05)"; ctx.lineWidth=1;
  for(let i=0;i<=4;i++){const y=pad.t+ch*(1-i/4); ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(pad.l+cw,y); ctx.stroke();}
  const maxV=Math.max(1,...series.flatMap(s=>keys.map(k=>s[k]||0)));
  const xS=t2=>pad.l+(t2/DURATION)*cw, yS=v=>pad.t+ch*(1-v/maxV);
  keys.forEach((key,ki)=>{
    ctx.beginPath(); let first=true;
    series.forEach((s,si)=>{ if(si>tBin) return; const x=xS(s.t),y=yS(s[key]||0); first?(ctx.moveTo(x,y),first=false):ctx.lineTo(x,y); });
    ctx.strokeStyle=colors[ki]; ctx.lineWidth=1.8; ctx.stroke();
    ctx.fillStyle=colors[ki]; ctx.font="8px sans-serif"; ctx.textAlign="left"; ctx.fillText(labels[ki],pad.l+4+ki*70,pad.t+9);
  });
  const cx2=xS(Math.min(t,DURATION));
  ctx.beginPath(); ctx.moveTo(cx2,pad.t); ctx.lineTo(cx2,pad.t+ch); ctx.strokeStyle="rgba(63,185,80,.7)"; ctx.lineWidth=1.5; ctx.stroke();
  ctx.fillStyle="#4a5568"; ctx.font="8px sans-serif"; ctx.textAlign="right";
  [0,.5,1].forEach(f=>ctx.fillText(Math.round(maxV*f),pad.l-3,pad.t+ch*(1-f)+3));
  ctx.textAlign="center"; ctx.fillStyle="#4a5568";
  [0,.25,.5,.75,1].forEach(f=>{const s=Math.round(DURATION/1000*f); ctx.fillText(Math.floor(s/60)+"m"+(s%60)+"s",pad.l+cw*f,pad.t+ch+13);});
}

function updateStatus(t){
  const bi=Math.min(Math.floor(t/BIN),DATA.ts.length-1);
  const s=DATA.ts[bi]||{};
  document.getElementById("s-ac").textContent=(s.an||0)+(s.aa||0);
  document.getElementById("s-aa").textContent=s.aa||0;
  document.getElementById("s-ok").textContent=s.ok||0;
  document.getElementById("s-ad").textContent=s.ac||0;
  document.getElementById("s-fc").textContent=s.fc||0;
  document.getElementById("time-disp").textContent=(t/1000).toFixed(0)+" s / "+(DURATION/1000).toFixed(0)+" s";
  const pct=Math.min(t/DURATION,1)*100;
  document.getElementById("tl-cur").style.left=pct+"%";
  document.getElementById("tl-fill").style.width=pct+"%";
}

function redraw(){
  drawNet(simTime);
  drawChart("ch-active",["aa","an"],["#ff7b72","#4a5568"],["hold中","通常"],simTime);
  drawChart("ch-cum",["ok","ac","fc"],["#3fb950","#ff7b72","#f85149"],["成功","攻撃遅延","失敗"],simTime);
  updateStatus(simTime);
}
function frame(ts){
  if(!playing) return;
  if(lastTs!==null) simTime=Math.min(simTime+(ts-lastTs)*sliderVal*BASE_MUL, DURATION);
  lastTs=ts;
  redraw();
  if(simTime>=DURATION){ playing=false; document.getElementById("btn-play").textContent="▶ 再生"; return; }
  requestAnimationFrame(frame);
}

function resizeAll(){
  nc.width=nc.offsetWidth; nc.height=nc.offsetHeight; updateScale();
  ["ch-active","ch-cum"].forEach(id=>{const c=document.getElementById(id); c.width=c.offsetWidth; c.height=c.offsetHeight;});
}

document.getElementById("btn-play").addEventListener("click",()=>{
  playing=!playing;
  document.getElementById("btn-play").textContent=playing?"⏸ 一時停止":"▶ 再生";
  if(playing){ lastTs=null; requestAnimationFrame(frame); }
});
document.getElementById("btn-reset").addEventListener("click",()=>{
  simTime=0; playing=false; lastTs=null;
  document.getElementById("btn-play").textContent="▶ 再生"; redraw();
});
document.getElementById("spd").addEventListener("input",e=>{
  sliderVal=+e.target.value;
  document.getElementById("spd-lbl").textContent=sliderVal+"×（毎秒"+sliderVal+"件）";
});
document.getElementById("tl-outer").addEventListener("click",e=>{
  const b=e.currentTarget.getBoundingClientRect();
  simTime=Math.max(0,Math.min(1,(e.clientX-b.left)/b.width))*DURATION; redraw();
});

const ro=new ResizeObserver(()=>{resizeAll(); redraw();});
ro.observe(document.getElementById("net-wrap"));
ro.observe(document.getElementById("right"));
window.addEventListener("load",()=>{resizeAll(); redraw();});
resizeAll(); redraw();
</script>
</body></html>"""

# ── サイドバー ────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### CLoTH-Gossip 可視化")
    results_dir = st.text_input("結果ディレクトリのパス",
        placeholder="/path/to/results/dir", key="results_dir_input")
    rep_override = st.text_input("評判ファイル（任意・攻撃者識別用）",
        placeholder="未指定なら同一run内から自動探索",
        key="rep_override_input",
        help="no_defense条件には評判ファイルが無いため、同一runのmethod2から自動探索します。手動指定も可。")
    load_btn = st.button("読み込み＆構築", type="primary", use_container_width=True)
    st.divider()
    st.markdown("""**操作方法（全てグラフ内で完結）**
- ▶ 再生 / ⏸ 一時停止 / ↺ リセット
- 速度スライダー: **1×（毎秒1件）〜5000×**
- 下部タイムラインをクリックでシーク

**決済の往復（行き・帰り）**
- <span style='color:#79c0ff'>①送金</span>: HTLC設定が送信者→受信者へ（行き）
- <span style='color:#56d364'>②決済確定</span>: preimageが受信者→送信者へ逆流（帰り・成功）
- <span style='color:#f85149'>②失敗通知</span>: 失敗が送信者へ逆流（帰り・失敗）
- <span style='color:#ff5050'>hold攻撃</span>: 攻撃者ノードでHTLCが停止（帰り無し）

※行き/帰りは1決済の時間窓を前半・後半に分けて表示しています（LNのHTLCは往路で設定・復路で確定/取消される二段階動作）。

**ノード色**
<span style='color:#58a6ff'>●</span> ハブ　<span style='color:#f85149'>●</span> 攻撃者　<span style='color:#3fb950'>●</span> 監視者　<span style='color:#3d4450'>●</span> 通常
""", unsafe_allow_html=True)

# ── メイン ────────────────────────────────────────────────────────
if load_btn and results_dir:
    st.session_state.loaded_dir = results_dir
    st.session_state.loaded_rep = rep_override or ""

if "loaded_dir" not in st.session_state or not st.session_state.loaded_dir:
    st.markdown("""
## 使い方
1. 左サイドバーに結果ディレクトリのパスを入力
2. **読み込み＆構築** をクリック（初回のみCSV読込に数秒）
3. グラフ内の **▶ 再生** で開始、速度スライダーで 1×〜5000× に調整

**必要ファイル:** `payments_output.csv`, `edges_output.csv`
（`reputation_dynamics.csv` は攻撃者識別用。no_defense条件のように無い場合は同一runから自動探索）

**速度の目安:** 1× = 毎秒約1件（じっくり観察）／ 5000× = 全期間を数秒で早送り
""")
    st.stop()

ldir = st.session_state.loaded_dir
lrep = st.session_state.get("loaded_rep", "")

# 読み込み進度バー（初回=キャッシュミス時のみ実際に動く。ヒット時は一瞬で消える）
_bar = st.progress(0.0, text="データ読み込み準備中...")
def _cb(frac, text):
    try: _bar.progress(min(max(frac, 0.0), 1.0), text=text)
    except Exception: pass
data_json, meta, err = build_payload(ldir, lrep, _progress=_cb)
_bar.progress(1.0, text="完了")
_bar.empty()
if err:
    st.error(err); st.stop()

# サマリー行
c1,c2,c3,c4,c5 = st.columns(5)
c1.metric("条件", meta["label"])
c2.metric("ノード数", f"{meta['N_nodes']:,}")
c3.metric("総取引数", f"{meta['n_total']:,}")
c4.metric("経路描画数", f"{meta['n_disp']:,}")
c5.metric("総時間", f"{meta['DURATION']/1000:.0f}s")

# 評判ファイルの状態表示
if meta["rep_path"]:
    if not meta["rep_path"].startswith(ldir):
        st.info(f"攻撃者/監視者の識別に別ディレクトリの評判ファイルを自動使用: "
                f"`{meta['rep_path']}`（攻撃者{meta['n_mal']}・監視者{meta['n_mon']}）")
else:
    st.warning("評判ファイルが見つからないため、攻撃者・監視者ノードは色分けされません"
               "（攻撃を受けた取引の経路は attack_delay_events から橙色で表示されます）。")

# Canvas埋め込み（アニメーションは全てiframe内JSで完結）
html = HTML_TEMPLATE.replace("__DATA_JSON__", data_json)
components.html(html, height=640, scrolling=False)

st.caption(f"経路の走る支払いは hops付き全 {meta['n_disp']:,} 件（サンプリングなし）。"
           "速度スライダーの 1× は「支払いが毎秒およそ1件開始する」速さに校正しています"
           f"（全期間 {meta['DURATION']/1000:.0f} 秒）。"
           "全ての操作はグラフ内で完結するため、再生中に画面が再構築されることはありません。")
