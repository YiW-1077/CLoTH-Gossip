#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/cmake-build-debug"

# ============================================================
# === 攻撃手法の選択（この値を直接編集して切り替える）===
#   ATTACK_MODE=1 : hold-to-timeout 型のみ（HTLCを保持してタイムアウト失敗させる; 旧称 fail型/forward型）
#   ATTACK_MODE=2 : hold 型のみ（決済保持グリーフィング）
#   ATTACK_MODE=3 : 混在（hold-to-timeout + hold; 割合は下の GRIEF_HOLD_RATIO）
# (sweep 側 run_monitor_sweep.sh と同期: hold(2)。変える場合は両方揃えること)
ATTACK_MODE=2
GRIEF_HOLD_RATIO=0.5    # ATTACK_MODE=3 のときの hold 割合 [0,1]
# 代役ハブ (what-if): run_monitor_sweep.sh と同じく、判定をする方式 (judging_strategy が disabled 以外) の
# シナリオにだけ入れる (悪意のハブ (次数 100 以上) 1 つにつき 1 個・オラクル配置)。0 で無効
SUBSTITUTE_COUNT=1
# ============================================================
export CLOTH_ATTACK_MODE="$ATTACK_MODE"
[ "$ATTACK_MODE" = "3" ] && export CLOTH_GRIEF_HOLD_RATIO="$GRIEF_HOLD_RATIO"
[ "$ATTACK_MODE" != "1" ] && export CLOTH_DETECT_GRIEF="${CLOTH_DETECT_GRIEF:-1}"  # 案B (CLOTH_HOLD_ROUNDTRIP=0) 用。既定の案A はこれによらず走る
echo "[Config] 攻撃手法 ATTACK_MODE=$ATTACK_MODE (1=hold-to-timeout 2=hold 3=mix)  DETECT_GRIEF=${CLOTH_DETECT_GRIEF:-0}  HOLD_RATIO=${CLOTH_GRIEF_HOLD_RATIO:-n/a}"
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
enable_judge_movement=false
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
judging_strategy=$monitoring"
  
  # ビルド。cmake-build-debug は CLion が作る Ninja 形式なので make ではなく cmake --build を使う
  cmake --build "$BUILD_DIR" >/dev/null 2>&1 || { echo "build failed"; return 1; }

  local outdir="/tmp/scenario-$name"
  rm -rf "$outdir"
  mkdir -p "$outdir"

  # シナリオごとの作業場所で走らせる。CLoTH_Gossip はカレントの config/cloth_input.txt を読み、
  # カレントに payments.csv を書くので、プロジェクト直下で走らせると git で管理している
  # config/cloth_input.txt (sweep も元にする) をシナリオの設定で上書きしてしまっていた (2026-10-14 に修正)。
  # 作業場所にはシナリオの設定と入力データ (symlink) だけを置き、終わったら消す。
  local work="$outdir/_work" f
  mkdir -p "$work/config/data"
  echo "$config" > "$work/config/cloth_input.txt"
  for f in nodes_ln.csv channels_ln.csv edges_ln.csv; do
    ln -s "$PROJECT_ROOT/config/data/$f" "$work/config/data/$f"
    ln -s "$PROJECT_ROOT/$f" "$work/$f"   # ランダム網の生成 (generate_network_from_file=false) はカレントの *_ln.csv を読む
  done
  # 代役なしのシナリオでも空で渡し、シェルに残った CLOTH_SUBSTITUTE_COUNT を引き継がない
  local sub_env="CLOTH_SUBSTITUTE_COUNT="
  if [ "$monitoring" != "disabled" ] && [ "$SUBSTITUTE_COUNT" -gt 0 ]; then
    sub_env="CLOTH_SUBSTITUTE_COUNT=$SUBSTITUTE_COUNT CLOTH_SUBSTITUTE_MIN_DEGREE=100 CLOTH_SUBSTITUTE_MAX_LINKS=400 CLOTH_SUBSTITUTE_ON_DETECTION=0"
  fi
  echo "[Config] 代役ハブ: ${sub_env}"
  ( cd "$work" && env $sub_env GSL_RNG_SEED=42 "$BUILD_DIR/CLoTH_Gossip" "$outdir/" ) 2>&1 | grep -E "Time consumed|success_rate|n_successful" | tail -5
  rm -rf "$work"
  
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
