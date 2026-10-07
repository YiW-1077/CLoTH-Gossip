#!/bin/bash
# =============================================================================
# 攻撃モデル現実化グリッド: 「注入遅延のばらつき」×「攻撃ノード割合」で検出率を測る
# -----------------------------------------------------------------------------
#  軸1 攻撃遅延分布 (CLOTH_ATTACK_DELAY_DIST):
#       fixed       = 従来 (保持時間が常に base×intensity = 一律 +100ms)
#       lognormal   = 平均保存・対数正規 (σ=CLOTH_ATTACK_DELAY_SIGMA, 既定1.0)
#       exponential = 平均保存・指数分布 (メモリレスな保持時間)
#       ※ いずれも E[X]=1 なので「平均注入遅延は fixed と同一・分散だけ変わる」
#  軸2 攻撃ノード割合 (malicious_node_ratio): 0.15(従来) → 0.10 → 0.05 → 0.02
#  軸3 取引数 n_payments
#
# 条件は run_monitor_sweep.sh の防御セル(method2 / avoid_low_reputation)に合わせるが、
# 交絡を避けるため代役ハブ(SUBSTITUTE)は OFF に固定する:
#   代役注入は「悪意ハブ(degree>=100)ごとに1個」なので、攻撃割合を変えるとトポロジ
#   パッチ自体が変わってしまい、検出率の変化が分布/割合由来か代役由来か分離できない。
#   → 本グリッドの数値は代役ONのsweep結果とは直接比較しないこと。
#
# Usage: ./scripts/run_attack_realism_grid.sh <out_dir> [seed] [dists] [ratios] [ns]
# Example: ./scripts/run_attack_realism_grid.sh /tmp/realism_grid 42
# =============================================================================
set -u

project_root="$(cd "$(dirname "$0")/.." && pwd)"
out_base="${1:?usage: $0 <out_dir> [seed]}"
seed="${2:-42}"
IFS=',' read -r -a DISTS  <<< "${3:-fixed,lognormal,exponential}"
IFS=',' read -r -a RATIOS <<< "${4:-0.15,0.10,0.05,0.02}"
IFS=',' read -r -a NS     <<< "${5:-1600,6400}"

BIN="$project_root/cmake-build-debug/CLoTH_Gossip"
[ -x "$BIN" ] || { echo "ERROR: binary not found: $BIN (cmake --build cmake-build-debug)"; exit 1; }

max_processes="${MAX_PROCESSES:-12}"
P_VALUE="${P_VALUE:-0.001}"
AVG_PMT="${AVG_PMT:-100}"
SIGMA="${CLOTH_ATTACK_DELAY_SIGMA:-1.0}"
# 平均保持時間そのものを変えたいときは INTENSITY を上げる (2.0 = 従来の +100ms 相当)。
# 分布軸は平均保存なので、平均の効果はこのノブでしか動かない。
INTENSITY="${INTENSITY:-2.0}"

# --- work dir テンプレート ----------------------------------------------------
# ⚠️ work dir はセルごとに分ける必要がある。本体の generate_random_payments() は
#    **カレントディレクトリの payments.csv** に決済列を書き出してから読み直すため、
#    複数セルで cwd を共有すると並列プロセスが互いの payments.csv を上書きし、
#    「n=1600 のセルが n=6400 の決済列を読む」等の取り違えが起きる (実測で確認)。
#    run-simulation.sh が毎回プロジェクトを rsync していたのはこの隔離のためでもある。
work_tpl="$out_base/_work_template"
mkdir -p "$work_tpl/config"
cp "$project_root/config/cloth_input.txt" "$work_tpl/config/cloth_input.txt"
# env オーバーライドが無いパラメータだけ config を書き換える (sweep の防御セルと同値)
sed -i '' \
    -e 's/^mpp=.*/mpp=0/' \
    -e 's/^payment_timeout=.*/payment_timeout=200000/' \
    -e "s/^average_payment_amount=.*/average_payment_amount=$AVG_PMT/" \
    -e "s/^variance_payment_amount=.*/variance_payment_amount=$((AVG_PMT / 10))/" \
    -e 's/^attack_delay_jitter=.*/attack_delay_jitter=0.0/' \
    "$work_tpl/config/cloth_input.txt"

# セル専用の work dir を作る (入力 CSV は symlink、config は実体コピー)
make_cell_work() {
    local w="$1"
    mkdir -p "$w/config"
    cp "$work_tpl/config/cloth_input.txt" "$w/config/cloth_input.txt"
    local f
    for f in nodes_ln.csv channels_ln.csv edges_ln.csv; do
        ln -sf "$project_root/$f" "$w/$f"
    done
}

echo "============================================================"
echo " 攻撃モデル現実化グリッド"
echo "   seed          : $seed"
echo "   分布          : ${DISTS[*]}  (lognormal σ=$SIGMA)"
echo "   攻撃ノード割合: ${RATIOS[*]}"
echo "   取引数        : ${NS[*]}"
echo "   固定条件      : method2 / p=$P_VALUE / amount=$AVG_PMT / hold攻撃(mode2) / 代役OFF"
echo "   並列          : $max_processes"
echo "   出力          : $out_base"
echo "============================================================"

# 本体は稀に SIGSEGV で落ちることがある (run-simulation.sh も max_attempts=5 で
# リトライする設計)。同一 seed なので再実行すれば同じ結果が出る。
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"

run_cell_once() {
    local dist="$1" ratio="$2" n="$3"
    local cell="$out_base/dist=$dist/ratio=$ratio/n=$n"
    local cwork="$cell/_work"
    mkdir -p "$cell"
    make_cell_work "$cwork"
    (
        cd "$cwork" || exit 1
        env GSL_RNG_SEED="$seed" \
            CLOTH_N_ADDITIONAL_NODES=6000 \
            CLOTH_N_PAYMENTS="$n" \
            CLOTH_MALICIOUS_NODE_RATIO="$ratio" \
            CLOTH_MALICIOUS_FAILURE_PROBABILITY=1.0 \
            CLOTH_MONITORING_STRATEGY=method2 \
            CLOTH_MONITOR_NODE_LIMIT=10 \
            CLOTH_TOP_HUB_COUNT=10 \
            CLOTH_ENABLE_PRT=true CLOTH_ENABLE_RBR=true \
            CLOTH_ENABLE_MONITOR_MOVEMENT=false \
            CLOTH_ENABLE_NETWORK_ATTACK_DELAY=true CLOTH_ATTACK_DELAY_INTENSITY="$INTENSITY" \
            CLOTH_ATTACK_MODE=2 CLOTH_DETECT_GRIEF=1 \
            CLOTH_SETTLE_DEGREE_SIGMA=0.20 \
            CLOTH_NULL_DEGREE_SIGMA=0.04 CLOTH_RATE_GATE_TAU=0.001 \
            CLOTH_PVALUE_THRESHOLD="$P_VALUE" \
            CLOTH_SUBSTITUTE_COUNT=0 \
            CLOTH_ATTACK_DELAY_DIST="$dist" CLOTH_ATTACK_DELAY_SIGMA="$SIGMA" \
            nice -n 4 "$BIN" "$cell/" > "$cell/cloth.log" 2>&1
    ) 2>/dev/null
}

run_cell() {
    local dist="$1" ratio="$2" n="$3"
    local cell="$out_base/dist=$dist/ratio=$ratio/n=$n"
    local attempt=1 rc=1
    # 健全性: 実際に処理された非warmup決済数が指定 n と一致すること。
    # (payments.csv の取り違え・途中終了・0件終了をここで弾く)
    cell_ok() {
        [ -f "$cell/summary.csv" ] || return 1
        local tp
        tp=$(grep "^total_payments," "$cell/summary.csv" 2>/dev/null | cut -d',' -f2 | tr -d '[:space:]')
        [ "$tp" = "$n" ]
    }
    # 再開: 既に完走しているセルは再実行しない (RESUME=0 で無効化)
    if [ "${RESUME:-1}" = "1" ] && cell_ok; then
        echo "  [skip] dist=$dist ratio=$ratio n=$n (既存)"
        return 0
    fi
    while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
        run_cell_once "$dist" "$ratio" "$n"
        rc=$?
        if [ $rc -eq 0 ] && cell_ok; then break; fi
        echo "  [retry $attempt/$MAX_ATTEMPTS rc=$rc] dist=$dist ratio=$ratio n=$n"
        attempt=$((attempt + 1))
    done
    if [ $rc -eq 0 ] && cell_ok; then
        rm -rf "$cell/_work"
        echo "  [done] dist=$dist ratio=$ratio n=$n"
    else
        echo "  [FAIL rc=$rc] dist=$dist ratio=$ratio n=$n (see $cell/cloth.log)"
    fi
}

started=0
for dist in "${DISTS[@]}"; do
  for ratio in "${RATIOS[@]}"; do
    for n in "${NS[@]}"; do
        while [ "$(jobs -rp | wc -l)" -ge "$max_processes" ]; do sleep 2; done
        run_cell "$dist" "$ratio" "$n" &
        started=$((started + 1))
        echo "  [start $started] dist=$dist ratio=$ratio n=$n"
    done
  done
done
wait
echo "全 $started セル完了。集計します..."

# --- 集計 -------------------------------------------------------------------
summary_csv="$out_base/results_grid.csv"
{
  echo "dist,sigma,intensity,malicious_ratio,n_payments,total_malicious,observable_attacked,detected_attackers,detection_rate_pct,precision_pct,false_positives,n_successful,success_rate_pct,avg_delay_ms,attacks_triggered,payments_griefed,grief_delay_total_ms"
  for dist in "${DISTS[@]}"; do
    for ratio in "${RATIOS[@]}"; do
      for n in "${NS[@]}"; do
        cell="$out_base/dist=$dist/ratio=$ratio/n=$n"
        sm="$cell/summary.csv"; bm="$cell/baseline_metrics.csv"
        [ -f "$sm" ] || continue
        g() { grep "^$1," "$sm" 2>/dev/null | cut -d',' -f2 | tr -d '[:space:]'; }
        b() { awk -F',' -v k="$1" 'NR==1{for(i=1;i<=NF;i++) if($i==k) c=i} NR==2 && c{print $c}' "$bm" 2>/dev/null; }
        sig="-"; [ "$dist" = "lognormal" ] && sig="$SIGMA"
        echo "$dist,$sig,$INTENSITY,$ratio,$n,$(g total_malicious_nodes),$(g observable_attacked_malicious_nodes),$(g detected_malicious_nodes),$(g malicious_detection_rate_observable_attacked_percent),$(g malicious_detection_precision_percent),$(g false_positive_nodes),$(g successful_payments),$(g payment_success_rate_percent),$(b avg_delay),$(b total_attacks_triggered),$(b payments_with_attack_delay),$(b attack_delay_total)"
      done
    done
  done
} > "$summary_csv"

echo "集計: $summary_csv"
column -s, -t "$summary_csv"
