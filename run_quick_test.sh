#!/bin/bash
set -e

PROJECT_ROOT="/Users/oukihisashi/CLionProjects/CLoTH-Gossip"
BASE_CONFIG="$PROJECT_ROOT/config/cloth_input.txt"
BUILD_DIR="$PROJECT_ROOT/cmake-build-debug"

# ============================================================
# === 攻撃手法の選択（この値を直接編集して切り替える）===
#   ATTACK_MODE=1 : fail 型のみ（従来の HTLC 失敗攻撃）
#   ATTACK_MODE=2 : hold 型のみ（決済保持グリーフィング）
#   ATTACK_MODE=3 : 混在（fail + hold; 割合は下の GRIEF_HOLD_RATIO）
# (sweep 側 run_monitor_sweep.sh と同期: hold(2)。変える場合は両方揃えること)
ATTACK_MODE=2
GRIEF_HOLD_RATIO=0.5    # ATTACK_MODE=3 のときの hold 割合 [0,1]
# ============================================================
export CLOTH_ATTACK_MODE="$ATTACK_MODE"
[ "$ATTACK_MODE" = "3" ] && export CLOTH_GRIEF_HOLD_RATIO="$GRIEF_HOLD_RATIO"
[ "$ATTACK_MODE" != "1" ] && export CLOTH_DETECT_GRIEF="${CLOTH_DETECT_GRIEF:-1}"  # mode2/3で決済検知器を自動ON
echo "[Config] 攻撃手法 ATTACK_MODE=$ATTACK_MODE (1=fail 2=hold 3=mix)  DETECT_GRIEF=${CLOTH_DETECT_GRIEF:-0}  HOLD_RATIO=${CLOTH_GRIEF_HOLD_RATIO:-n/a}"
BASE_TEMPLATE='generate_network_from_file=true
nodes_filename=config/data/nodes_ln.csv
channels_filename=config/data/channels_ln.csv
edges_filename=config/data/edges_ln.csv
n_additional_nodes=
n_channels_per_node=
capacity_per_channel=
faulty_node_probability=0.0
generate_payments_from_file=false
payment_timeout=60000
average_payment_forward_interval=100
variance_payment_forward_interval=1
routing_method=cloth_original
group_size=5
group_limit_rate=0.1
group_cap_update=true
group_broadcast_delay=0
payments_filename=
payment_rate=1
n_payments=100
average_payment_amount=100
variance_payment_amount=10
average_max_fee_limit=-1
variance_max_fee_limit=-1
enable_fake_balance_update=false
cul_threshold_dist_alpha=2
cul_threshold_dist_beta=10
mpp=1
enable_network_attack_delay=false
attack_delay_start_time=30000
attack_delay_duration=30000
attack_delay_intensity=1.0
attack_delay_jitter=0.0
hub_degree_threshold=50
top_hub_count=30
enable_simple_progress_mode=false
enable_simple_progress_window=false
reputation_decay_rate=0.01
reputation_penalty_on_detection=0.3
reputation_recovery_rate=0.02
enable_monitor_movement=false
movement_credit_limit=5
enable_pra=false
enable_prt=true
prt_threshold=30
prt_abort_wait_time=1000
rbr_reputation_weight=20.0'

test_scenario() {
  local name=$1 malicious=$2 attack_success=$3 rbr=$4 rep=$5 monitoring=$6
  
  echo ""
  echo "========================================="
  echo "Scenario $name"
  echo "========================================="
  
  local config="$BASE_TEMPLATE
malicious_node_ratio=$malicious
malicious_failure_probability=$attack_success
enable_reputation_system=$rep
enable_rbr=$rbr
monitoring_strategy=$monitoring"
  
  echo "$config" > "$BASE_CONFIG"
  
  # ビルドは build ディレクトリで実行
  ( cd "$BUILD_DIR" && cmake .. >/dev/null 2>&1 && make >/dev/null 2>&1 ) || { echo "build failed"; return 1; }

  local outdir="/tmp/scenario-$name"
  rm -rf "$outdir"
  mkdir -p "$outdir"

  # 実行は PROJECT_ROOT をカレントにする。CLoTH_Gossip はカレントの config/cloth_input.txt
  # (fallback: cloth_input.txt) を読むため、build ディレクトリで実行すると CMake が
  # build/config/ へコピーした設定 (CMakeLists.txt:9 でルート直下 cloth_input.txt 由来)
  # が読まれ、本スクリプトが $BASE_CONFIG に書いたシナリオ設定が反映されない。
  # ルートで実行すれば $BASE_CONFIG と config/data/ が直接使われる。
  ( cd "$PROJECT_ROOT" && GSL_RNG_SEED=42 "$BUILD_DIR/CLoTH_Gossip" "$outdir/" ) 2>&1 | grep -E "Time consumed|success_rate|n_successful" | tail -5
  
  echo "Metrics:"
  cat "$outdir/baseline_metrics.csv" | awk -F',' '{print "  Success: " $4 "%, Avg Delay: " $5}'
}

test_scenario "A" "0.0" "0.0" "false" "false" "disabled"
test_scenario "B" "0.3" "0.8" "false" "false" "disabled"
test_scenario "C" "0.3" "0.8" "true"  "true"  "disabled"
test_scenario "D" "0.3" "0.8" "false" "false" "method1"
test_scenario "E" "0.3" "0.8" "true"  "true"  "method1"

echo ""
echo "Summary:"
for s in A B C D E; do
  echo -n "Scenario $s: "
  cat /tmp/scenario-$s/baseline_metrics.csv | tail -1 | awk -F',' '{printf "%.2f%% success\n", $4}'
done
