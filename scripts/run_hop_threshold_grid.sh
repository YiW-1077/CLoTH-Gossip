#!/bin/bash
# =============================================================================
# 経路長ベース閾値の効果測定: σ_eff = σ·(1 + k_deg·ln(1+deg) + k_hop·ln(1+nh))
# -----------------------------------------------------------------------------
# 「多重検定の露出」を何で測るかを比べる:
#   k_deg (CLOTH_SETTLE_DEGREE_SIGMA) = ノード次数で測る (現行既定 0.20)
#   k_hop (CLOTH_SETTLE_HOP_SIGMA)    = その決済が通るノード数=経路ホップ数で測る (新規)
# 攻撃者の中央次数は 24-38 なので ln(1+deg)≈3.2-3.6、経路は nh=3-5 で ln(1+nh)≈1.4-1.8。
# 同じ k なら経路長版のほうが null が狭く recall 側に振れる。FP 予算の配り直しが
# 効くのか、それとも単に「膨張を減らしただけ」なのかを arm=none(膨張なし)で切り分ける。
#
# 攻撃モデルは現実寄りの lognormal(σ=1, 平均保存) に固定する。fixed では recall が
# 既に ~100% で天井に当たっており、閾値を動かしても差が出ないため。
#
# Usage: ./scripts/run_hop_threshold_grid.sh <out_dir> [seed]
# =============================================================================
set -u

project_root="$(cd "$(dirname "$0")/.." && pwd)"
out_base="${1:?usage: $0 <out_dir> [seed]}"
seed="${2:-42}"

BIN="$project_root/cmake-build-debug/CLoTH_Gossip"
[ -x "$BIN" ] || { echo "ERROR: binary not found: $BIN"; exit 1; }

max_processes="${MAX_PROCESSES:-8}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"
P_VALUE="${P_VALUE:-0.001}"
AVG_PMT=100
DIST="${DIST:-lognormal}"
SIGMA="${SIGMA:-1.0}"

# arm = ラベル:k_deg:k_hop[:D]  (D=CLOTH_SETTLE_DEGREE_MIN, 省略時0=従来の ln(1+deg))
# (env ARMS_LIST/RATIOS_LIST/NS_LIST でカンマ区切り上書き可)
ARMS=(
  "deg020:0.20:0"      # 現行既定 (次数のみ)
  "hop020:0:0.20"      # 経路長のみ (同じ k)
  "hop040:0:0.40"      # 経路長のみ・強め (膨張量を次数版に近づける)
  "mix:0.10:0.20"      # 併用
  "none:0:0"           # 膨張なし (recall 上限と FP の出方を見る対照)
)
RATIOS=(0.15 0.05)
NS=(1600 6400)
[ -n "${ARMS_LIST:-}" ]   && IFS=',' read -r -a ARMS   <<< "$ARMS_LIST"
[ -n "${RATIOS_LIST:-}" ] && IFS=',' read -r -a RATIOS <<< "$RATIOS_LIST"
[ -n "${NS_LIST:-}" ]     && IFS=',' read -r -a NS     <<< "$NS_LIST"

# --- work dir テンプレート (セルごとに複製。cwd 共有は payments.csv 競合を起こす) ---
work_tpl="$out_base/_work_template"
mkdir -p "$work_tpl/config"
cp "$project_root/config/cloth_input.txt" "$work_tpl/config/cloth_input.txt"
sed -i '' \
    -e 's/^mpp=.*/mpp=0/' \
    -e 's/^payment_timeout=.*/payment_timeout=200000/' \
    -e "s/^average_payment_amount=.*/average_payment_amount=$AVG_PMT/" \
    -e "s/^variance_payment_amount=.*/variance_payment_amount=$((AVG_PMT / 10))/" \
    -e 's/^attack_delay_jitter=.*/attack_delay_jitter=0.0/' \
    "$work_tpl/config/cloth_input.txt"

make_cell_work() {
    local w="$1" f
    mkdir -p "$w/config"
    cp "$work_tpl/config/cloth_input.txt" "$w/config/cloth_input.txt"
    for f in nodes_ln.csv channels_ln.csv edges_ln.csv; do ln -sf "$project_root/$f" "$w/$f"; done
}

echo "============================================================"
echo " 経路長ベース閾値グリッド  seed=$seed  攻撃=$DIST(σ=$SIGMA)"
echo "   arms  : ${ARMS[*]}"
echo "   ratios: ${RATIOS[*]}   n: ${NS[*]}   並列: $max_processes"
echo "   出力  : $out_base"
echo "============================================================"

run_cell_once() {
    local arm="$1" kdeg="$2" khop="$3" dmin="$4" ratio="$5" n="$6"
    local cell="$out_base/arm=$arm/ratio=$ratio/n=$n"
    local cwork="$cell/_work"
    mkdir -p "$cell"; make_cell_work "$cwork"
    (
        cd "$cwork" || exit 1
        env GSL_RNG_SEED="$seed" \
            CLOTH_N_ADDITIONAL_NODES=6000 CLOTH_N_PAYMENTS="$n" \
            CLOTH_MALICIOUS_NODE_RATIO="$ratio" CLOTH_MALICIOUS_FAILURE_PROBABILITY=1.0 \
            CLOTH_MONITORING_STRATEGY=method2 CLOTH_MONITOR_NODE_LIMIT=10 CLOTH_TOP_HUB_COUNT=10 \
            CLOTH_ENABLE_PRT=true CLOTH_ENABLE_RBR=true CLOTH_ENABLE_MONITOR_MOVEMENT=false \
            CLOTH_ENABLE_NETWORK_ATTACK_DELAY=true CLOTH_ATTACK_DELAY_INTENSITY=2.0 \
            CLOTH_ATTACK_MODE=2 CLOTH_DETECT_GRIEF=1 \
            CLOTH_SETTLE_DEGREE_SIGMA="$kdeg" CLOTH_SETTLE_HOP_SIGMA="$khop" \
            CLOTH_SETTLE_DEGREE_MIN="$dmin" \
            CLOTH_NULL_DEGREE_SIGMA=0.04 CLOTH_RATE_GATE_TAU=0.001 \
            CLOTH_PVALUE_THRESHOLD="$P_VALUE" CLOTH_SUBSTITUTE_COUNT=0 \
            CLOTH_ATTACK_DELAY_DIST="$DIST" CLOTH_ATTACK_DELAY_SIGMA="$SIGMA" \
            nice -n 4 "$BIN" "$cell/" > "$cell/cloth.log" 2>&1
    ) 2>/dev/null
}

run_cell() {
    local arm="$1" kdeg="$2" khop="$3" dmin="$4" ratio="$5" n="$6"
    local cell="$out_base/arm=$arm/ratio=$ratio/n=$n"
    local attempt=1 rc=1
    cell_ok() {
        [ -f "$cell/summary.csv" ] || return 1
        local tp; tp=$(grep "^total_payments," "$cell/summary.csv" 2>/dev/null | cut -d',' -f2 | tr -d '[:space:]')
        [ "$tp" = "$n" ]
    }
    if [ "${RESUME:-1}" = "1" ] && cell_ok; then echo "  [skip] $arm r=$ratio n=$n"; return 0; fi
    while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
        run_cell_once "$arm" "$kdeg" "$khop" "$dmin" "$ratio" "$n"; rc=$?
        if [ $rc -eq 0 ] && cell_ok; then break; fi
        echo "  [retry $attempt/$MAX_ATTEMPTS] $arm r=$ratio n=$n"; attempt=$((attempt + 1))
    done
    if [ $rc -eq 0 ] && cell_ok; then rm -rf "$cell/_work"; echo "  [done] $arm r=$ratio n=$n"
    else echo "  [FAIL] $arm r=$ratio n=$n (see $cell/cloth.log)"; fi
}

for a in "${ARMS[@]}"; do
  IFS=':' read -r arm kdeg khop dmin <<< "$a"; dmin="${dmin:-0}"
  for ratio in "${RATIOS[@]}"; do
    for n in "${NS[@]}"; do
      while [ "$(jobs -rp | wc -l)" -ge "$max_processes" ]; do sleep 2; done
      run_cell "$arm" "$kdeg" "$khop" "$dmin" "$ratio" "$n" &
    done
  done
done
wait
echo "完了。集計します..."

summary_csv="$out_base/results_hop.csv"
{
  echo "arm,k_deg,k_hop,degree_min,malicious_ratio,n_payments,observable_attacked,detected_attackers,detection_rate_pct,precision_pct,false_positives,total_flagged,success_rate_pct,grief_delay_total_ms"
  for a in "${ARMS[@]}"; do
    IFS=':' read -r arm kdeg khop dmin <<< "$a"; dmin="${dmin:-0}"
    for ratio in "${RATIOS[@]}"; do
      for n in "${NS[@]}"; do
        cell="$out_base/arm=$arm/ratio=$ratio/n=$n"; sm="$cell/summary.csv"; bm="$cell/baseline_metrics.csv"
        [ -f "$sm" ] || continue
        g() { grep "^$1," "$sm" 2>/dev/null | cut -d',' -f2 | tr -d '[:space:]'; }
        b() { awk -F',' -v k="$1" 'NR==1{for(i=1;i<=NF;i++) if($i==k) c=i} NR==2 && c{print $c}' "$bm" 2>/dev/null; }
        echo "$arm,$kdeg,$khop,$dmin,$ratio,$n,$(g observable_attacked_malicious_nodes),$(g detected_malicious_nodes),$(g malicious_detection_rate_observable_attacked_percent),$(g malicious_detection_precision_percent),$(g false_positive_nodes),$(g total_flagged_nodes),$(g payment_success_rate_percent),$(b attack_delay_total)"
      done
    done
  done
} > "$summary_csv"
echo "集計: $summary_csv"
column -s, -t "$summary_csv"
