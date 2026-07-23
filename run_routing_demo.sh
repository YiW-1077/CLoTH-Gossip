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
# 末尾で起動する可視化アプリ:
#   search  : 経路探索(Dijkstra)の可視化 … 探索がどう広がり最短経路が決まるかを見る
#   flow    : 決済の流れの可視化           … ①送金→②決済確定の往復を時系列で見る
#   compare : 4手法くらべ                  … 手法で経路が分かれた送金を1件ずつ比較(要 ROUTING_METHOD=all)
VIZ_APP=compare
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
# ビルドログは実行ごとに一意なパスへ（共有Macで他ユーザ所有の固定名ファイルと衝突し
# Permission denied になるのを防ぐ）。$$=PID で各実行・各ユーザ固有。
BUILD_LOG="${TMPDIR:-/tmp}/routing_demo_build.$$.log"
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
average_payment_amount=2000
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
  #   CLOTH_LOG_SEARCH=true: 実際の経路探索(Dijkstra)の探索過程を search_log.csv に記録する。
  #     → 可視化アプリが「実際の探索と全く同じ」波面を再生できる(再現ではなく本物)。
  local start end
  start=$(date +%s)
  ( cd "$PROJECT_ROOT" && GSL_RNG_SEED=$SEED CLOTH_LOG_SEARCH=true "$BINARY" "$outdir/" ) \
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
  if cmake --build "$BUILD_DIR" > "$BUILD_LOG" 2>&1; then
    echo "[ビルド] 完了。"
  else
    echo "[エラー] ビルドに失敗しました。ログ: $BUILD_LOG"
    tail -15 "$BUILD_LOG"
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

# ── 起動する可視化アプリを決定（VIZ_APP）──────────────────────────────────
case "$VIZ_APP" in
  search)  APP_FILE="dijkstra_viz_app.py";  APP_DESC="経路探索(Dijkstra)の可視化" ;;
  flow)    APP_FILE="cloth_sim_viz_app.py"; APP_DESC="決済の流れの可視化" ;;
  compare) APP_FILE="routing_compare_app.py"; APP_DESC="4手法くらべ(経路の違い)"
           if [ ${#SELECTED[@]} -lt 4 ]; then
             echo "[注意] VIZ_APP=compare は4手法の比較です。ROUTING_METHOD=all で全手法を実行してください。"
             echo "        現在の実行対象: ${SELECTED[*]}"
           fi ;;
  *)       echo "[エラー] VIZ_APP は search / flow / compare のいずれかを指定してください（現在: '$VIZ_APP'）"; exit 1 ;;
esac

# ── 完了メッセージ ───────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " シミュレーション完了。$APP_DESC を起動します。"
echo "============================================================"
if [ "$VIZ_APP" = "search" ]; then
  echo "   ※ 受信者(中心)から探索が波状に広がり、送信者(外周)に到達→最短経路を強調表示。"
  echo "     ▶再生で確定ノードが順に光ります。コスト基準を変えると選ばれる経路が変わります。"
elif [ "$VIZ_APP" = "compare" ]; then
  echo "   ※ 4手法の実経路を比べ、手法で経路が分かれた送金を1件ずつ表示します。"
  echo "     ⏮前/次⏭で移動。手法差は estimate_capacity(容量の見積もり方)の違いだけです。"
else
  echo "   ※ 決済は「①送金(青・行き)」→「②決済確定(緑・帰り)」の往復で表示されます。"
fi
if [ "$VIZ_APP" != "compare" ] && [ ${#SELECTED[@]} -gt 1 ]; then
  echo "   ※ 複数手法を実行しました。他手法を見るときはサイドバーのパスを貼り替えてください："
  for m in "${SELECTED[@]}"; do echo "        $OUT_BASE/$m"; done
fi

# ── 可視化アプリを起動（デモ出力を自動読み込み）─────────────────────────────
VIZ_DIR="$PROJECT_ROOT/repro_out_fig"
# 最初に実行した手法の出力をアプリの初期表示にする（環境変数で連携）
export CLOTH_VIZ_DIR="$OUT_BASE/${SELECTED[0]}"

# config を先に元へ戻す（この後アプリが長時間フォアグラウンドで動くため）
restore_config
trap - EXIT   # 復元済みなので EXIT トラップは解除

# streamlit を探す（教育用ブランチには .venv が無い場合があるためフォールバック）
if [ -x "$VIZ_DIR/.venv/bin/streamlit" ]; then
  STREAMLIT="$VIZ_DIR/.venv/bin/streamlit"
elif command -v streamlit >/dev/null 2>&1; then
  STREAMLIT="streamlit"
else
  echo ""
  echo "[注意] streamlit が見つかりません。次でインストール後、手動起動してください："
  echo "        pip install streamlit"
  echo "        cd $VIZ_DIR && streamlit run $APP_FILE"
  exit 0
fi

echo ""
echo "ブラウザで http://localhost:8501 が開きます（初期表示: ${SELECTED[0]}）。"
echo "停止するにはこのターミナルで Ctrl-C を押してください。"
cd "$VIZ_DIR" && "$STREAMLIT" run "$APP_FILE"
