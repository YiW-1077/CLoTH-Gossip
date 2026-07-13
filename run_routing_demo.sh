#!/opt/homebrew/bin/bash
# =============================================================================
# run_routing_demo.sh
#   CLoTH の「経路探索(ルーティング)手法」を選んで実行し、
#   可視化アプリ(cloth_sim_viz_app.py)で動きを観察するための教育用スクリプト。
#
#   ねらい（後輩向け）:
#     - シミュレータを実際に自分で実行する経験をする
#     - ルーティング手法によって「どの経路で送金が流れるか」が変わる様子を体験する
#
#   使い方:
#     1) 下の「実行する経路探索手法」の値を編集する
#     2) ./run_routing_demo.sh を実行する
#     3) 表示される出力パスを可視化アプリに貼り付けて再生する
# =============================================================================
set -e

# ============================================================================
# === 実行する経路探索手法（この値を直接編集して切り替える）===
#   cloth_original    : 元々のCLoTH。LNの実際のルーティングを忠実に再現（基準）
#   group_routing     : edgeグループ（グループ単位の容量制限方式）
#   ideal             : edge残高を直接利用（理想・性能上限比較用/プライバシー無視）
#   group_routing_cul : edgeグループ + CUL(累積利用率)閾値方式
#   all               : 上記4手法をすべて順に実行して比較
# (enum には channel_update もあるが、ソースで「間違っているので未使用」とされるため対象外)
ROUTING_METHOD=all
# ============================================================================

# ── 実験パラメータ（自由に編集してよい）──────────────────────────────────
N_PAYMENTS=2000     # 決済数。多いほど時間がかかる（2000で約17秒/手法）
SEED=42             # 乱数シード（同じ値なら毎回同じ結果になる = 再現性）
# =========================================================================

# ── パス設定（このスクリプトの場所を基準に自動決定）───────────────────────
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/cmake-build-debug"
BINARY="$BUILD_DIR/CLoTH_Gossip"
CONFIG="$PROJECT_ROOT/config/cloth_input.txt"
OUT_BASE="$PROJECT_ROOT/repro_out_fig/routing_demo"

# ─────────────────────────────────────────────────────────────────────────
# 【重要】このスクリプトは共有設定ファイル config/cloth_input.txt を書き換えます。
#   後輩が次に手動実行したとき、デモが残した設定で動いてしまうのを防ぐため、
#   開始時にバックアップし、終了時（正常/異常/Ctrl-C いずれでも）に必ず復元します。
# ─────────────────────────────────────────────────────────────────────────
CONFIG_BACKUP="/tmp/cloth_input_demo_backup.$$"
if [ -f "$CONFIG" ]; then cp "$CONFIG" "$CONFIG_BACKUP"; fi
restore_config() {
  if [ -f "$CONFIG_BACKUP" ]; then
    cp "$CONFIG_BACKUP" "$CONFIG"
    rm -f "$CONFIG_BACKUP"
    echo "[復元] config/cloth_input.txt を元の内容に戻しました。"
  fi
}
trap restore_config EXIT

# ── 各ルーティング手法の説明（include/core/cloth.h のコメント準拠）─────────
# NOTE: enum routing_method には channel_update もあるが、ソースのコメントに
#       「間違っているので未使用」とあるため、このデモでは除外している。
#       ＝「元々のcloth_original + 3種類(group_routing/ideal/group_routing_cul)」
describe_method() {
  case "$1" in
    cloth_original)
      echo "  元々のCLoTHに実装されていたルーティング。"
      echo "  Lightning Network の実際のルーティングを忠実に再現したもの（基準となる手法）。" ;;
    group_routing)
      echo "  edgeグループを用いるルーティング。"
      echo "  グループごとに min_cap_limit / max_cap_limit を設け、グループ内edgeは必ずこの範囲を満たす。" ;;
    ideal)
      echo "  edgeの残高をそのままルーティングに利用する理想手法。"
      echo "  最大性能の比較用なのでプライバシーを一切考慮しない（現実には知り得ない残高を使う）。" ;;
    group_routing_cul)
      echo "  edgeグループ + CUL(累積利用率)閾値方式のルーティング。"
      echo "  edgeごとに cul_threshold_factor を設定し、グループ内edgeのCULが必ずこの閾値以下になるようにする。" ;;
    *)
      echo "  (不明な手法)" ;;
  esac
}

# ── 指定手法用の config/cloth_input.txt を生成 ────────────────────────────
#    攻撃・監視はOFF（純粋にルーティングの挙動を観察するため）。
write_config() {
  local method="$1"
  cat > "$CONFIG" << EOF
generate_network_from_file=true
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
routing_method=$method
group_size=5
group_limit_rate=0.1
group_cap_update=true
group_broadcast_delay=0
payments_filename=
payment_rate=1
n_payments=$N_PAYMENTS
average_payment_amount=100
variance_payment_amount=10
average_max_fee_limit=-1
variance_max_fee_limit=-1
enable_fake_balance_update=false
cul_threshold_dist_alpha=2
cul_threshold_dist_beta=10
mpp=0
malicious_node_ratio=0.0
malicious_failure_probability=0.0
enable_network_attack_delay=false
attack_delay_start_time=0
attack_delay_duration=0
attack_delay_intensity=1.0
attack_delay_jitter=0.0
hub_degree_threshold=50
monitoring_strategy=disabled
top_hub_count=30
enable_simple_progress_mode=false
enable_simple_progress_window=false
enable_reputation_system=false
reputation_decay_rate=0.01
reputation_penalty_on_detection=0.3
reputation_recovery_rate=0.02
enable_monitor_movement=false
movement_credit_limit=5
enable_pra=false
enable_prt=false
prt_threshold=30
prt_abort_wait_time=1000
enable_rbr=false
rbr_reputation_weight=20.0
EOF
}

# ── 1手法を実行 ───────────────────────────────────────────────────────────
run_method() {
  local method="$1"
  local outdir="$OUT_BASE/$method"

  echo ""
  echo "============================================================"
  echo " 経路探索手法: $method"
  echo "============================================================"
  describe_method "$method"
  echo ""
  echo "  決済数=$N_PAYMENTS  シード=$SEED"
  echo "  出力先: $outdir"
  echo "  実行中... (約 $((N_PAYMENTS / 120)) 秒程度)"

  write_config "$method"
  rm -rf "$outdir"
  mkdir -p "$outdir"

  # PROJECT_ROOT をカレントにして実行する。
  #   CLoTH_Gossip はカレントの config/cloth_input.txt を読むため、必ずここで実行する。
  #   (build ディレクトリで実行すると CMake がコピーした別の設定が読まれてしまう)
  local start end
  start=$(date +%s)
  ( cd "$PROJECT_ROOT" && GSL_RNG_SEED=$SEED "$BINARY" "$outdir/" ) \
      > "$outdir/run_stdout.log" 2>&1
  end=$(date +%s)

  # 結果の要約を表示
  local succ total
  if [ -f "$outdir/payments_output.csv" ]; then
    total=$(($(wc -l < "$outdir/payments_output.csv") - 1))
    succ=$(awk -F',' 'NR>1 && $9==1' "$outdir/payments_output.csv" | wc -l | tr -d ' ')
    echo "  完了 ($(($end - $start)) 秒)  決済 $total 件中 成功 $succ 件"
  else
    echo "  [警告] payments_output.csv が生成されませんでした。ログ: $outdir/run_stdout.log"
  fi
}

# ── ビルド（バイナリが無い or ソースが新しければ）─────────────────────────
build_if_needed() {
  echo "[ビルド] CLoTH_Gossip をビルドします..."
  if cmake --build "$BUILD_DIR" > /tmp/routing_demo_build.log 2>&1; then
    echo "[ビルド] 完了。"
  else
    echo "[エラー] ビルドに失敗しました。ログ: /tmp/routing_demo_build.log"
    tail -15 /tmp/routing_demo_build.log
    exit 1
  fi
}

ALL_METHODS=(cloth_original group_routing ideal group_routing_cul)

# ── スクリプト先頭の ROUTING_METHOD を検証して実行対象を確定 ──────────────
resolve_methods() {
  if [ "$ROUTING_METHOD" = "all" ]; then
    SELECTED=("${ALL_METHODS[@]}"); return
  fi
  for m in "${ALL_METHODS[@]}"; do
    if [ "$m" = "$ROUTING_METHOD" ]; then SELECTED=("$ROUTING_METHOD"); return; fi
  done
  echo "[エラー] ROUTING_METHOD の値が不正です: '$ROUTING_METHOD'"
  echo "         スクリプト先頭の ROUTING_METHOD を次のいずれかに編集してください:"
  echo "         ${ALL_METHODS[*]} / all"
  exit 1
}

# ── メイン ────────────────────────────────────────────────────────────────
resolve_methods
echo "[選択] ROUTING_METHOD=$ROUTING_METHOD  →  実行対象: ${SELECTED[*]}"
build_if_needed
mkdir -p "$OUT_BASE"

for m in "${SELECTED[@]}"; do
  run_method "$m"
done

# ── 完了メッセージ & 可視化の案内 ─────────────────────────────────────────
echo ""
echo "============================================================"
echo " すべて完了しました。"
echo "============================================================"
echo ""
echo "▼ 可視化アプリで観察する手順:"
echo "   1) ターミナルで可視化アプリを起動:"
echo "        cd $PROJECT_ROOT/repro_out_fig"
echo "        .venv/bin/streamlit run cloth_sim_viz_app.py"
echo "   2) ブラウザ(http://localhost:8501)の左サイドバー「結果ディレクトリのパス」に"
echo "      下記のいずれかを貼り付けて「読み込み＆構築」→「▶再生」:"
for m in "${SELECTED[@]}"; do
  echo "        $OUT_BASE/$m"
done
echo ""
echo "   ※ 決済は「①送金(青・行き)」→「②決済確定(緑・帰り)」の往復で表示されます。"
echo "     手法によって選ばれる経路(通るノード)が変わる様子を見比べてください。"
