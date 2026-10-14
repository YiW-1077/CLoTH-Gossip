#!/bin/bash
# =============================================================================
# 偽報告(嘘の報告)への耐性検証
# -----------------------------------------------------------------------------
# 悪意ノードは報告者にもなれるので、自分の観測時刻を水増しして
#   (a) 自分への嫌疑を縮める(自己免罪) (b) 下流隣接ノードを陥れる(冤罪)
# ことができる。これを CLOTH_FALSE_REPORT_MS[ms] で注入し、帰属方式を変えて比較する。
#
#   CLOTH_REPORT_ATTEST=0 : 旧方式。被疑ノード自身の申告 RT を使って Δ=RT[i]-RT[i+1]。
#   CLOTH_REPORT_ATTEST=1 : 相互証明 (既定)。被疑ノードの申告を使わず両隣の申告だけで
#                           hold[p] = recv[p-1] - send_back[p+1] を構成する。同一イベントの
#                           二者申告が許容差を超えたときの扱いは DISPUTE_POLICY / SINGLE_DISPUTE /
#                           TRUST_SENDER・TRUST_RECEIVER に従う (10/09 以降の既定は 4a+端点信頼+ペア集計)。
#                           ⚠️ このスクリプトは SINGLE_DISPUTE・TRUST_* を渡さないのでコードの既定で走る。
#                           10/06 の結果を再現するなら 0 を明示すること。
#   CLOTH_CLOCK_SKEW_MS=E : 各ノードの固定時計オフセット(-E..+E)。相互証明は
#                           ノードをまたぐ突き合わせなので E に敏感、旧方式は
#                           自ノード内の差分なので理屈上は不感。
#
# Usage: ./scripts/run_false_report_grid.sh <out_dir> [seed]
#   結果は NAS (REMOTE_OUTPUT_DIR、省略で <nas.conf の候補>/<out_dir の名前>) に置く。out_dir は走っている
#   間の作業場所で、終わったセルから NAS へ移す。REMOTE_OUTPUT_DIR=local のときだけローカルに残す。
#   置き場所にもうセルがあると止まる。続きから回すときは RESUME=1 (scripts/nas_lib.sh)。
# =============================================================================
set -u
project_root="$(cd "$(dirname "$0")/.." && pwd)"
out_base="${1:?usage: $0 <out_dir> [seed]}"
seed="${2:-42}"
BIN="$project_root/cmake-build-debug/CLoTH_Gossip"
[ -x "$BIN" ] || { echo "ERROR: binary not found"; exit 1; }
source "$project_root/scripts/nas_lib.sh"
nas_setup "$out_base" || exit 1

max_processes="${MAX_PROCESSES:-8}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"
N="${N:-6400}"
RATIO="${RATIO:-0.15}"
# 代役ハブ (what-if): run_monitor_sweep.sh の防御モードと同じ既定 (悪意のハブ (次数 100 以上) 1 つにつき
# 正直な代役を 1 つ・オラクル配置)。このグリッドは method2 (防御モード) だけなので全セルに入る。0 で無効
SUBSTITUTE_COUNT="${SUBSTITUTE_COUNT:-1}"

# cell = ラベル:attest:lie_ms:skew_ms[:lie_prob[:silent_prob[:silence_policy[:dispute_policy]]]]
CELLS=(
  "cur_lie0:0:0:0"      "att_lie0:1:0:0"       # 嘘なし(基準)
  "cur_lie50:0:50:0"    "att_lie50:1:50:0"
  "cur_lie100:0:100:0"  "att_lie100:1:100:0"
  "cur_lie200:0:200:0"  "att_lie200:1:200:0"
  "att_lie100_sk10:1:100:10"                   # 時計ずれ耐性
  "att_lie100_sk25:1:100:25"
  "att_lie100_sk50:1:100:50"
  "att_lie100_sk100:1:100:100"
  "cur_lie100_sk50:0:100:50"                   # 現行方式が skew に不感かの確認
)
[ -n "${CELLS_LIST:-}" ] && IFS=',' read -r -a CELLS <<< "$CELLS_LIST"

work_tpl="$out_base/_work_template"
mkdir -p "$work_tpl/config"
cp "$project_root/config/cloth_input.txt" "$work_tpl/config/cloth_input.txt"
sed -i '' -e 's/^mpp=.*/mpp=0/' -e 's/^payment_timeout=.*/payment_timeout=200000/' \
    -e 's/^average_payment_amount=.*/average_payment_amount=100/' \
    -e 's/^variance_payment_amount=.*/variance_payment_amount=10/' \
    -e 's/^attack_delay_jitter=.*/attack_delay_jitter=0.0/' "$work_tpl/config/cloth_input.txt"

make_cell_work() {
    local w="$1" f
    mkdir -p "$w/config"; cp "$work_tpl/config/cloth_input.txt" "$w/config/cloth_input.txt"
    for f in nodes_ln.csv channels_ln.csv edges_ln.csv; do ln -sf "$project_root/$f" "$w/$f"; done
}

echo "============================================================"
echo " 偽報告耐性グリッド  seed=$seed  n=$N  ratio=$RATIO  代役ハブ=$SUBSTITUTE_COUNT  並列=$max_processes"
echo " cells: ${#CELLS[@]}"
echo "============================================================"

run_once() {
    local lbl="$1" att="$2" lie="$3" sk="$4" pr="$5" sq="$6" sp="$7" dp="$8"
    local cell="$out_base/$lbl" cwork="$out_base/$lbl/_work"
    mkdir -p "$cell"; make_cell_work "$cwork"
    (
        cd "$cwork" || exit 1
        env GSL_RNG_SEED="$seed" \
            CLOTH_N_ADDITIONAL_NODES=6000 CLOTH_N_PAYMENTS="$N" \
            CLOTH_MALICIOUS_NODE_RATIO="$RATIO" CLOTH_MALICIOUS_FAILURE_PROBABILITY=1.0 \
            CLOTH_JUDGING_STRATEGY=method2 CLOTH_JUDGE_NODE_LIMIT=10 CLOTH_TOP_HUB_COUNT=10 \
            CLOTH_ENABLE_PRT=true CLOTH_ENABLE_RBR=true CLOTH_ENABLE_JUDGE_MOVEMENT=false \
            CLOTH_ENABLE_NETWORK_ATTACK_DELAY=true CLOTH_ATTACK_DELAY_INTENSITY=2.0 \
            CLOTH_ATTACK_MODE=2 CLOTH_DETECT_GRIEF=1 \
            CLOTH_SETTLE_DEGREE_SIGMA=0.20 CLOTH_NULL_DEGREE_SIGMA=0.04 CLOTH_RATE_GATE_TAU=0.001 \
            CLOTH_PVALUE_THRESHOLD=0.001 CLOTH_SUBSTITUTE_COUNT="$SUBSTITUTE_COUNT" CLOTH_SUBSTITUTE_MIN_DEGREE=100 CLOTH_SUBSTITUTE_MAX_LINKS=400 CLOTH_SUBSTITUTE_ON_DETECTION=0 \
            CLOTH_ATTACK_DELAY_DIST=lognormal CLOTH_ATTACK_DELAY_SIGMA=1.0 \
            CLOTH_REPORT_ATTEST="$att" CLOTH_FALSE_REPORT_MS="$lie" CLOTH_CLOCK_SKEW_MS="$sk" \
            CLOTH_FALSE_REPORT_PROB="$pr" CLOTH_SILENT_REPORT_PROB="$sq" CLOTH_ATTEST_SILENCE_POLICY="$sp" CLOTH_ATTEST_DISPUTE_POLICY="$dp" ${VAR_INIT:+CLOTH_SETTLE_VAR_INIT=$VAR_INIT} \
            nice -n 4 "$BIN" "$cell/" > "$cell/cloth.log" 2>&1
    ) 2>/dev/null
}

run_cell() {
    local lbl="$1" att="$2" lie="$3" sk="$4" pr="$5" sq="$6" sp="$7" dp="$8"
    local cell="$out_base/$lbl" a=1 rc=1
    ok() { [ -f "$1/summary.csv" ] && \
           [ "$(grep '^total_payments,' "$1/summary.csv" 2>/dev/null | cut -d, -f2 | tr -d ' ')" = "$N" ]; }
    if [ "${RESUME:-0}" = "1" ]; then
        if ok "$cell"; then echo "  [skip] $lbl"; nas_cell_done "$cell"; return 0; fi
        if [ -n "$NAS_DEST" ] && ok "$NAS_DEST/$lbl"; then echo "  [skip] $lbl (NAS)"; return 0; fi
    fi
    while [ "$a" -le "$MAX_ATTEMPTS" ]; do
        run_once "$lbl" "$att" "$lie" "$sk" "$pr" "$sq" "$sp" "$dp"; rc=$?
        if [ $rc -eq 0 ] && ok "$cell"; then break; fi
        echo "  [retry $a] $lbl"; a=$((a+1))
    done
    if [ $rc -eq 0 ] && ok "$cell"; then rm -rf "$cell/_work"; echo "  [done] $lbl"
    else echo "  [FAIL] $lbl"; fi
    nas_cell_done "$cell"
}

for c in "${CELLS[@]}"; do
    IFS=':' read -r lbl att lie sk pr sq sp dp <<< "$c"; pr="${pr:-1.0}"; sq="${sq:-0}"; sp="${sp:-0}"; dp="${dp:-0}"
    while [ "$(jobs -rp | wc -l)" -ge "$max_processes" ]; do sleep 2; done
    run_cell "$lbl" "$att" "$lie" "$sk" "$pr" "$sq" "$sp" "$dp" &
done
wait
nas_finish
echo "完了。集計: python3 scripts/summarize_false_report.py $RESULT_BASE"
