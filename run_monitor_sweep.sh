#!/opt/homebrew/bin/bash
# 監視手法スイープシミュレーション（並列実行）
# 3手法 (monitor_disable=no_defense baseline / monitor_method1 / monitor_method2) を
# 取引数 N_PAYMENTS × 支払額 PAYMENT_AMOUNTS × p値 P_VALUES の全組み合わせで実行する。
# 防御は method に固定対応: disable→no_defense(PRT/RBR off), method1/2→avoid_low_reputation(PRT/RBR on)。
# 防御2モードには代役ハブ(what-if)を既定で注入する(下の SUBSTITUTE_COUNT 参照)。
# Usage: ./run_monitor_sweep.sh <seed> <output_base_dir> [remote_output_dir_or_smb_uri] [key=value ...]
# Example: ./run_monitor_sweep.sh 42 /output/dir monitoring_strategy=method1

if [ $# -lt 2 ]; then
    echo "Usage: $0 <seed[,seed...]> <output_base_dir> [remote_output_dir_or_smb_uri] [key=value ...]"
    echo "Example: $0 42 /output/dir monitoring_strategy=method1"
    echo "Example(複数シード): $0 42,123 /output/dir <remote> ...   # 42→123 の順に実行"
    exit 1
fi

# --- 複数シード対応 ---------------------------------------------------------
# $1 にカンマ/空白区切りで複数シードを指定すると、各シードで本スクリプトを
# 順番に自己再実行する(各シードは独立した timestamp 出力dir + results_summary.csv)。
# 単一シードのときは何もせず通常処理へフォールスルー。
IFS=', ' read -r -a _seeds <<< "$1"
if [ "${#_seeds[@]}" -gt 1 ]; then
    echo "[Config] 複数シード検出: ${_seeds[*]} → 順番に実行します"
    _multi_rc=0
    for _s in "${_seeds[@]}"; do
        [ -z "$_s" ] && continue
        echo ""
        echo "########################################################"
        echo "### シード $_s 実行開始 ($(date '+%Y-%m-%d %H:%M:%S'))"
        echo "########################################################"
        "$0" "$_s" "${@:2}" || _multi_rc=$?
    done
    echo ""
    echo "########################################################"
    echo "### 全シード完了: ${_seeds[*]} (rc=$_multi_rc)"
    echo "########################################################"
    exit $_multi_rc
fi
# ---------------------------------------------------------------------------

seed_base="$1"
output_base_arg="$2"
remote_arg="${3:-${REMOTE_OUTPUT_DIR:-}}"
project_root="$(cd "$(dirname "$0")" && pwd)"

# Process additional keyword arguments for monitoring_strategy override and p_list
MONITORING_METHODS_OVERRIDE=""
# P_VALUES are specified here inside the script (override args/env)
# Edit this list to change which p-value thresholds are tested.
P_VALUES=(0.01 0.005 0.001)

for ((i=4; i<=$#; i++)); do
    arg="${!i}"
    if [[ "$arg" == monitoring_strategy=* ]]; then
        strategy_value="${arg#monitoring_strategy=}"
        case "$strategy_value" in
            disabled|disable)
                MONITORING_METHODS_OVERRIDE="monitor_disable"
                ;;
            method1)
                MONITORING_METHODS_OVERRIDE="monitor_method1"
                ;;
            method2)
                MONITORING_METHODS_OVERRIDE="monitor_method2"
                ;;
            all)
                MONITORING_METHODS_OVERRIDE="monitor_disable monitor_method1 monitor_method2"
                ;;
            *)
                echo "ERROR: Invalid monitoring_strategy: $strategy_value"
                echo "Valid options: disabled, method1, method2, all"
                exit 1
                ;;
        esac
        echo "[Config] Override MONITORING_METHODS: $MONITORING_METHODS_OVERRIDE"
    fi
    # NOTE: 旧 defense_mode=... オプションは削除した。パースはされるが enqueue ループは
    # method ごとに defense_modes_iter を固定でハードコードしており、一度も効いていない
    # 死んだノブだった (防御の実体は monitoring_strategy と enable_rbr/enable_prt の対で切替)。
    if [[ "$arg" == p_list=* ]]; then
        p_list_val="${arg#p_list=}"
        IFS=',' read -r -a P_VALUES <<< "$p_list_val"
        echo "[Config] P_VALUES: ${P_VALUES[*]}"
    fi
done
# Also accept environment variable CLOTH_PVALUE_LIST (comma-separated) if provided and P_VALUES empty
if [[ ${#P_VALUES[@]} -eq 0 && -n "${CLOTH_PVALUE_LIST:-}" ]]; then
    IFS=',' read -r -a P_VALUES <<< "${CLOTH_PVALUE_LIST}"
    echo "[Config] P_VALUES from env CLOTH_PVALUE_LIST: ${P_VALUES[*]}"
fi

# Create timestamped output directory (always local)
timestamp=$(date "+%Y%m%d%H%M%S")

# ---------------------------------------------------------------------------
# Fixed parameters
# ---------------------------------------------------------------------------
N_PAYMENTS=(50 100 200 400 800 1600 3200 6400 12800)
MALICIOUS_RATIO=0.15
ATTACK_SUCCESS_RATE=1.0
TOP_HUB_COUNT=10

ATTACK_DELAY_PARAMS_ON="enable_network_attack_delay=true  attack_delay_start_time=3000 attack_delay_duration=30000 attack_delay_intensity=2.0 attack_delay_jitter=0.0"

# ---------------------------------------------------------------------------
# FWER対策 (攻撃者検知 precision の n 依存低下の緩和) を全 sim で有効化。
#   CLOTH_NULL_DEGREE_SIGMA : degree-σ null。高次数ノードの仮説検定 null を
#                             広げて誤報告(FP源)を走行中に抑える (Axis-3)。
#   CLOTH_RATE_GATE_TAU     : report-rate gate。低レポートレートの flag を実行末に
#                             取り消す測定専用フィルタ (経路・評判には不干渉)。
# 検証値: k=0.04 + τ=1e-3 で FP 6->0 / precision 100% / recall 無損失。
# export なので各 sim (run-simulation.sh -> CLoTH_Gossip) に継承される。
# 外部で指定があればそれを優先 (空文字を export すれば無効化)。
# ---------------------------------------------------------------------------
export CLOTH_NULL_DEGREE_SIGMA="${CLOTH_NULL_DEGREE_SIGMA-0.04}"
export CLOTH_RATE_GATE_TAU="${CLOTH_RATE_GATE_TAU-0.001}"
echo "[Config] FWER対策 env: CLOTH_NULL_DEGREE_SIGMA=$CLOTH_NULL_DEGREE_SIGMA CLOTH_RATE_GATE_TAU=$CLOTH_RATE_GATE_TAU"

# ---------------------------------------------------------------------------
# === 攻撃手法の選択（この値を直接編集して切り替える）===
#   ATTACK_MODE=1 : fail 型のみ（従来の HTLC 失敗攻撃）
#   ATTACK_MODE=2 : hold 型のみ（決済保持グリーフィング）
#   ATTACK_MODE=3 : 混在（fail + hold; 割合は下の GRIEF_HOLD_RATIO）
# (8ce7590 で hold(2) に設定後、cb27298 で意図せず 3 に戻っていたのを再修正)
ATTACK_MODE=2
GRIEF_HOLD_RATIO=0.5   # ATTACK_MODE=3 のときの hold 割合 [0,1]
# ---------------------------------------------------------------------------
export CLOTH_ATTACK_MODE="$ATTACK_MODE"
[ "$ATTACK_MODE" = "3" ] && export CLOTH_GRIEF_HOLD_RATIO="$GRIEF_HOLD_RATIO"
[ "$ATTACK_MODE" != "1" ] && export CLOTH_DETECT_GRIEF="${CLOTH_DETECT_GRIEF:-1}"  # mode2/3で決済検知器を自動ON
echo "[Config] 攻撃手法 ATTACK_MODE=$ATTACK_MODE (1=fail 2=hold 3=mix)  DETECT_GRIEF=${CLOTH_DETECT_GRIEF:-0}  HOLD_RATIO=${CLOTH_GRIEF_HOLD_RATIO:-n/a}"

# ---------------------------------------------------------------------------
# === 代役ハブ(トポロジ what-if) — 防御2モードで既定ON ===
# 悪意ハブ(次数>=SUBSTITUTE_MIN_DEGREE)ごとに正直な代役ノードを注入し、回避で失われる
# 連結性を補う。baseline(no_defense/monitor_disable)には注入せず対照を現実のまま保ち、
# 防御2モード(method1/method2)にのみ注入して、RBR回避を使う防御側が正直な代替を活用できる形にする。
# ⚠️注意: 代役は「現実網では作れない正直容量」の上限measurement。method1/2 の成績には配備不能な
#   代役容量分が含まれる(hub-soft/boost抑制のような配備可能ポリシーとは別クラス)。結果解釈時に留意。
# 既定ON(=1)。全モードrealisticにしたい場合は SUBSTITUTE_COUNT=0 を env で指定して無効化。
# 配置モード SUBSTITUTE_ON_DETECTION: 0=オラクル配置(既定, init時から有効, what-if上限) /
#   1=検知トリガ(非オラクル, 対象ハブが検知された時点で有効化, 配備現実寄り)。防御モードの
#   env に明示的に固定するので、ユーザシェルにグローバル export があっても化けない(遮蔽)。
# env をグローバル export せず、手法別に per-run コマンドへプレフィックスする(下の method ループ参照)。
SUBSTITUTE_COUNT="${SUBSTITUTE_COUNT:-1}"
SUBSTITUTE_ON_DETECTION="${SUBSTITUTE_ON_DETECTION:-0}"   # 0=オラクル(既定) / 1=検知トリガ(非オラクル)
SUB_ENV_DEFENSE=""   # 防御モード(method1/2)にだけ付けるenv。disableには付けない。
if [ "$SUBSTITUTE_COUNT" -gt 0 ] 2>/dev/null; then
    SUB_ENV_DEFENSE="CLOTH_SUBSTITUTE_COUNT=$SUBSTITUTE_COUNT CLOTH_SUBSTITUTE_MIN_DEGREE=${SUBSTITUTE_MIN_DEGREE:-100} CLOTH_SUBSTITUTE_MAX_LINKS=${SUBSTITUTE_MAX_LINKS:-400} CLOTH_SUBSTITUTE_ON_DETECTION=$SUBSTITUTE_ON_DETECTION"
    if [ "$SUBSTITUTE_ON_DETECTION" = "1" ]; then sub_mode_lbl="検知トリガ(非オラクル)"; else sub_mode_lbl="オラクル配置(init時から有効)"; fi
    echo "[Config] 代役ハブ 既定ON(防御モードのみ・baselineは対照, what-if上限): $SUB_ENV_DEFENSE  配置=$sub_mode_lbl ※配備可能策ではない"
else
    echo "[Config] 代役ハブ OFF (SUBSTITUTE_COUNT=0 指定・全モードrealistic baseline)。"
fi

# 決済(hold)検知の per-node heavy-tail null。既定ON。各ノードが warmup 中に自分の
# (1-α)決済レイテンシ分位点 settle_anom_q を学習し post-warmup 凍結→多忙ハブの重い裾を
# 自ノード baseline で吸収し、高nの誤検知(FP)を潰す(precision 87%→99.6% @ n=25600-102400,
# seed7で確認)。代役ハブとは独立。防御モード(method1/2)のみに適用(no_defenseは検知OFFで
# 無関係)。旧グローバル lognormal null に戻したい場合は env SETTLE_QUANTILE_NULL=0。
SETTLE_QUANTILE_NULL="${SETTLE_QUANTILE_NULL:-1}"
if [ "$SETTLE_QUANTILE_NULL" = "1" ]; then
    DETECT_ENV_DEFENSE="CLOTH_SETTLE_NULL_QUANTILE=true"
    echo "[Config] per-node heavy-tail null 既定ON(防御モードのみ): $DETECT_ENV_DEFENSE"
else
    DETECT_ENV_DEFENSE=""
    echo "[Config] per-node heavy-tail null OFF (SETTLE_QUANTILE_NULL=0)。旧lognormal nullにフォールバック。"
fi

# ---------------------------------------------------------------------------
# Sweep parameters
# ---------------------------------------------------------------------------
NODE_SCALES=6000
PAYMENT_AMOUNTS=(100 500 1000)

# 監視ノード数の絶対数リスト
MONITOR_NODE_COUNTS=(10)
MONITORING_METHODS=(monitor_disable monitor_method1 monitor_method2)

# 防御モードは method に固定対応 (enqueue ループ内 defense_modes_iter):
#   monitor_disable → no_defense / monitor_method1・method2 → avoid_low_reputation

# Apply MONITORING_METHODS override if specified
if [[ -n "$MONITORING_METHODS_OVERRIDE" ]]; then
    MONITORING_METHODS=($MONITORING_METHODS_OVERRIDE)
fi

# ===========================================================================
# results_summary.csv 生成 (改善版・改善デルタ列付き / 純 bash+awk, 追加スクリプト無し)
# ---------------------------------------------------------------------------
# 出力列(論理グループ順):
#   [条件]     n_transactions, payment_amount_sat, defense_strategy, monitor_method, p_value, monitor_count
#   [攻撃/grief] attacks_triggered, payments_griefed, grief_delay_total_ms, grief_delay_change_vs_nodef_pct ★hold主指標
#   [決済結果] n_successful, n_failed, success_rate_pct, success_change_vs_nodef_pp, avg_delay_ms, avg_delay_change_vs_nodef_pct
#   [検知]     detection_rate_pct, detected_attackers, observable_attacked, rbr_penalized_nodes, detection_precision_pct
#   [手数料]   avg_fee_msat, avg_fee_rate_pct, avg_fee_change_vs_nomonitor_pct
#   [冗長]     payment_amount_msat (=sat*1000, 互換のため末尾)
# 改善デルタは同一 (payment_amount_sat, n_transactions) の no_defense を基準にした変化。
#   grief/delay/fee = %変化 (負=削減=改善)、success = ポイント差 (正=向上=改善)。
# grief_delay_change_vs_nodef_pct は全 n で算出する (base=0 のときのみ数学的に N/A)。
#   以前は小 n(<3200) を N/A で隠すガードを入れていたが、その小 n 異常の根因だった
#   攻撃遅延ゲートの不整合 (完了数 processed_payments>=500 vs warmup=開始index) を
#   htlc.c 側で per-payment !is_warmup に修正済みのためガードは撤去した。
#   ⚠️ この修正後のバイナリで再実行した sweep でのみ小 n が正常 (no_defense=被害最大・
#   grief_change が -45%→大nの-80%へ単調収束)。旧バイナリの既存 sweep 出力は小 n が
#   依然 stale (no_def=0→N/A や +数百%) なので、正しい値には要再実行。
# 行は n→amount→p→method でソート (同一条件の disable/method1/method2 が隣接=改善を縦読み)。
# ===========================================================================

# summary.csv から指定キーの値を取り出すヘルパー
get_summary_value() {
    local file="$1" key="$2"
    grep "^${key}," "$file" 2>/dev/null | cut -d',' -f2 | tr -d '[:space:]' || echo "N/A"
}

# payments_output.csv から成功決済(is_success==1, warmup 非除外)の手数料平均を返す
# 出力: "avg_fee_msat avg_fee_rate_pct" を空白区切り
calc_fee_stats() {
    local payments_file="$1"
    if [[ ! -f "$payments_file" ]]; then echo "N/A N/A"; return; fi
    awk -F',' '
    NR==1 { for (i=1;i<=NF;i++){ if($i=="is_success")col_ok=i; if($i=="total_fee")col_fee=i; if($i=="amount")col_amt=i } next }
    col_ok && col_fee && col_amt && $col_ok=="1" {
        fee_sum += $col_fee
        if ($col_amt > 0) rate_sum += $col_fee / $col_amt * 100
        n++
    }
    END { if (n>0) printf "%.2f %.6f", fee_sum/n, rate_sum/n; else printf "N/A N/A" }' "$payments_file"
}

generate_summary_csv() {
    local csv_output="$output_base/results_summary.csv"
    local raw_tmp="${csv_output}.raw.tmp"
    local reord_tmp="${csv_output}.reord.tmp"
    echo "Generating CSV summary: $csv_output"

    {
        # RAW ヘッダ (21列: 従来18 + 生3列)。並べ替え・デルタは後段 awk。
        echo "defense_strategy,monitor_method,p_value,payment_amount_sat,payment_amount_msat,monitor_count,n_transactions,n_successful,n_failed,success_rate_pct,avg_delay_ms,attacks_triggered,detection_rate_pct,detected_attackers,observable_attacked,detection_precision_pct,avg_fee_msat,avg_fee_rate_pct,grief_delay_total_ms,payments_griefed,rbr_penalized_nodes"

        for n_payment in "${N_PAYMENTS[@]}"; do
          for avg_pmt in "${PAYMENT_AMOUNTS[@]}"; do
            payment_msat=$((avg_pmt * 1000))
            for method in "${MONITORING_METHODS[@]}"; do
                if [[ "$method" == "monitor_disable" ]]; then
                    monitor_counts_csv=(0); def_options=(no_defense)
                else
                    monitor_counts_csv=("${MONITOR_NODE_COUNTS[@]}"); def_options=(avoid_low_reputation)
                fi
                for monitor_count in "${monitor_counts_csv[@]}"; do
                    if [ ${#P_VALUES[@]} -gt 0 ]; then p_iter=("${P_VALUES[@]}"); else p_iter=("N/A"); fi
                    for p in "${p_iter[@]}"; do
                        if [[ "$p" == "N/A" ]]; then pdir=""; else pdir="p_${p//./_}"; fi
                        for defense in "${def_options[@]}"; do
                            if [[ "$method" == "monitor_disable" ]]; then
                                rel_path="$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt"
                            else
                                rel_path="$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt/monitor_count=$monitor_count"
                            fi
                            [[ -n "$pdir" ]] && rel_path="$rel_path/$pdir"

                            sim_dir=""
                            if [[ -n "$remote_output_base" && -d "$remote_output_base/$rel_path" ]]; then
                                sim_dir="$remote_output_base/$rel_path"
                            fi
                            [[ -z "$sim_dir" && -d "$output_base/$rel_path" ]] && sim_dir="$output_base/$rel_path"
                            [[ -z "$sim_dir" ]] && continue

                            defense_strategy="no_defense"
                            [[ "$defense" == "avoid_low_reputation" ]] && defense_strategy="avoid_low_reputation"
                            monitor_method_short="disable"
                            [[ "$method" == "monitor_method1" ]] && monitor_method_short="method1"
                            [[ "$method" == "monitor_method2" ]] && monitor_method_short="method2"

                            n_transactions="N/A"; n_successful="N/A"; n_failed="N/A"
                            success_rate_pct="N/A"; avg_delay_ms="N/A"; attacks_triggered="0"
                            detection_rate_pct="N/A"; detection_precision_pct="N/A"
                            detected_attackers="N/A"; observable_attacked="N/A"
                            avg_fee_msat="N/A"; avg_fee_rate_pct="N/A"
                            grief_delay_total_ms="N/A"; payments_griefed="N/A"; rbr_penalized_nodes="N/A"

                            sm="$sim_dir/summary.csv"
                            if [ -f "$sm" ]; then
                                n_transactions=$(get_summary_value "$sm" "total_payments")
                                n_successful=$(get_summary_value "$sm" "successful_payments")
                                success_rate_pct=$(get_summary_value "$sm" "payment_success_rate_percent")
                                detection_rate_pct=$(get_summary_value "$sm" "malicious_detection_rate_observable_attacked_percent")
                                detected_attackers=$(get_summary_value "$sm" "detected_malicious_nodes")
                                observable_attacked=$(get_summary_value "$sm" "observable_attacked_malicious_nodes")
                                detection_precision_pct=$(get_summary_value "$sm" "malicious_detection_precision_percent")
                                if [[ "$n_transactions" != "N/A" && "$n_successful" != "N/A" ]]; then
                                    n_failed=$((n_transactions - n_successful))
                                fi
                            fi

                            # baseline_metrics.csv から avg_delay/攻撃/grief 系を取得
                            baseline_file="$sim_dir/baseline_metrics.csv"
                            if [ -f "$baseline_file" ]; then
                                IFS=',' read -ra headers <<< "$(head -n1 "$baseline_file")"
                                IFS=',' read -ra values  <<< "$(tail -n1 "$baseline_file")"
                                for i in "${!headers[@]}"; do
                                    case "${headers[$i]}" in
                                        avg_delay)                  avg_delay_ms="${values[$i]}" ;;
                                        total_attacks_triggered)    attacks_triggered="${values[$i]}" ;;
                                        attack_delay_total)         grief_delay_total_ms="${values[$i]}" ;;
                                        payments_with_attack_delay) payments_griefed="${values[$i]}" ;;
                                        rbr_detected_nodes)         rbr_penalized_nodes="${values[$i]}" ;;
                                    esac
                                done
                            fi

                            # avg_delay フォールバック (stage4 → summary)
                            stage_file="$sim_dir/stage4_comparison.csv"
                            if [[ "$avg_delay_ms" == "N/A" || -z "$avg_delay_ms" ]] && [ -f "$stage_file" ]; then
                                avg_delay_ms=$(grep "^avg_payment_delay_ms," "$stage_file" 2>/dev/null | cut -d',' -f2 | tr -d '[:space:]' || echo "N/A")
                            fi
                            if [[ "$avg_delay_ms" == "N/A" || -z "$avg_delay_ms" ]] && [ -f "$sm" ]; then
                                avg_delay_ms=$(get_summary_value "$sm" "time/average")
                            fi

                            # 手数料 (payments_output.csv)
                            payments_file="$sim_dir/payments_output.csv"
                            [ -f "$payments_file" ] && read -r avg_fee_msat avg_fee_rate_pct <<< "$(calc_fee_stats "$payments_file")"

                            printf '%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
                                "$defense_strategy" "$monitor_method_short" "$p" "$avg_pmt" "$payment_msat" "$monitor_count" \
                                "$n_transactions" "$n_successful" "$n_failed" "$success_rate_pct" "$avg_delay_ms" "$attacks_triggered" \
                                "$detection_rate_pct" "$detected_attackers" "$observable_attacked" "$detection_precision_pct" \
                                "$avg_fee_msat" "$avg_fee_rate_pct" "$grief_delay_total_ms" "$payments_griefed" "$rbr_penalized_nodes"
                        done
                    done
                done
            done
          done
        done
    } > "$raw_tmp"

    # === 改善デルタ + 列並べ替え (no_defense 基準, 2-pass awk) ===
    if awk 'BEGIN{FS=OFS=","}
      function pc(cur,base){ if(base==""||base=="N/A"||base+0==0||cur==""||cur=="N/A") return "N/A"; return sprintf("%.2f",(cur-base)/base*100) }
      function pp(cur,base){ if(base==""||base=="N/A"||cur==""||cur=="N/A") return "N/A"; return sprintf("%.2f",cur-base) }
      NR==FNR{
        if(FNR==1){ for(i=1;i<=NF;i++) c[$i]=i; next }
        if($c["defense_strategy"]=="no_defense" || $c["monitor_method"]=="disable"){
          k=$c["payment_amount_sat"] SUBSEP $c["n_transactions"];
          bg[k]=$c["grief_delay_total_ms"]; bd[k]=$c["avg_delay_ms"];
          bs[k]=$c["success_rate_pct"]; bf[k]=$c["avg_fee_msat"];
        }
        next
      }
      FNR==1{
        print "n_transactions","payment_amount_sat","defense_strategy","monitor_method","p_value","monitor_count","attacks_triggered","payments_griefed","grief_delay_total_ms","grief_delay_change_vs_nodef_pct","n_successful","n_failed","success_rate_pct","success_change_vs_nodef_pp","avg_delay_ms","avg_delay_change_vs_nodef_pct","detection_rate_pct","detected_attackers","observable_attacked","rbr_penalized_nodes","detection_precision_pct","avg_fee_msat","avg_fee_rate_pct","avg_fee_change_vs_nomonitor_pct","payment_amount_msat";
        next
      }
      {
        k=$c["payment_amount_sat"] SUBSEP $c["n_transactions"];
        gchg = pc($c["grief_delay_total_ms"], bg[k]);
        dchg = pc($c["avg_delay_ms"], bd[k]);
        schg = pp($c["success_rate_pct"], bs[k]);
        fchg = pc($c["avg_fee_msat"], bf[k]);
        print $c["n_transactions"],$c["payment_amount_sat"],$c["defense_strategy"],$c["monitor_method"],$c["p_value"],$c["monitor_count"],$c["attacks_triggered"],$c["payments_griefed"],$c["grief_delay_total_ms"],gchg,$c["n_successful"],$c["n_failed"],$c["success_rate_pct"],schg,$c["avg_delay_ms"],dchg,$c["detection_rate_pct"],$c["detected_attackers"],$c["observable_attacked"],$c["rbr_penalized_nodes"],$c["detection_precision_pct"],$c["avg_fee_msat"],$c["avg_fee_rate_pct"],fchg,$c["payment_amount_msat"];
      }' "$raw_tmp" "$raw_tmp" > "$reord_tmp"; then
        # 行ソート: n(数値)→amount(数値)→p(数値)→method(disable<method1<method2)
        { head -1 "$reord_tmp"; tail -n +2 "$reord_tmp" | sort -t, -k1,1n -k2,2n -k5,5n -k4,4; } > "$csv_output"
        rm -f "$raw_tmp" "$reord_tmp"
        echo "Summary CSV: $csv_output (改善デルタ列付き, 行=n→amount→p→method)"
    else
        echo "[WARN] delta/reorder post-process failed; raw 21列版を使用"
        mv "$raw_tmp" "$csv_output"; rm -f "$reord_tmp"
    fi

    # NAS 転送
    if [[ -n "$remote_output_base" ]]; then
        if mkdir -p "$remote_output_base" 2>/tmp/nas_final_error.log; then
            if cp "$csv_output" "$remote_output_base/results_summary.csv" 2>/tmp/nas_csv_error.log; then
                echo "✓ Summary CSV transferred to NAS"
            else
                echo "[ERROR] Failed to transfer summary CSV:"; cat /tmp/nas_csv_error.log 2>/dev/null || echo "No error details"
            fi
        else
            echo "[ERROR] Failed to create final NAS directory: $remote_output_base"; cat /tmp/nas_final_error.log 2>/dev/null || echo "No error details"
        fi
    fi
}

# --regen-summary <run_dir>: 既存 run のサマリのみ改善版で再生成して終了 (sim 実行なし)。
# 過去 run にも後付け適用可: ./run_monitor_sweep.sh --regen-summary /path/to/<timestamp>
if [[ "$1" == "--regen-summary" ]]; then
    [[ -n "$2" && -d "$2" ]] || { echo "usage: $0 --regen-summary <run_dir>"; exit 1; }
    output_base="$2"; remote_output_base=""
    generate_summary_csv
    exit 0
fi

# ---------------------------------------------------------------------------
max_processes=12
queue=()
running_processes=0
total_simulations=0
output_base="$output_base_arg/$timestamp"
mkdir -p "$output_base" || {
    echo "ERROR: Cannot create local output directory: $output_base"
    exit 1
}

# ---------------------------------------------------------------------------
# Handle remote output directory (SMB conversion to local mount path)
# ---------------------------------------------------------------------------
remote_output_base=""
if [[ -n "$remote_arg" ]]; then
    if [[ "$remote_arg" == smb://* ]]; then
        echo "WARN: unsupported SMB URI format: $remote_arg"
        echo "      mount SMB first and pass local mount path (e.g. /Volumes/public1/...)."
        remote_arg=""
    fi
    if [[ -n "$remote_arg" ]]; then
        remote_output_base="$remote_arg/$timestamp"
    fi
fi

# ---------------------------------------------------------------------------
# Move completed simulations to NAS (incremental transfer)
# ---------------------------------------------------------------------------
nas_counter_transferred="/tmp/nas_transferred_$$.cnt"
nas_counter_failed="/tmp/nas_failed_$$.cnt"
nas_error_log="/tmp/nas_transfer_errors_$$.log"
echo 0 > "$nas_counter_transferred"
echo 0 > "$nas_counter_failed"
> "$nas_error_log"

function move_completed_to_remote() {
    if [[ -z "$remote_output_base" ]]; then
        return 0
    fi

    mapfile -t simulation_progress_files < <(find "$output_base" -type f -name "progress.tmp" ! -path "*/environment/*" 2>/dev/null)

    for file in "${simulation_progress_files[@]}"; do
        sim_dir="$(dirname "$file")"

        if [[ -f "$sim_dir/.moved_to_remote" ]]; then
            continue
        fi

        progress=$(cat "$file" 2>/dev/null || echo "0")

        if [[ "$progress" != "1" && "$progress" != "failed" ]]; then
            continue
        fi

        rel_path="${sim_dir#$output_base/}"
        if [[ "$rel_path" == "$sim_dir" ]]; then
            continue
        fi

        dest_dir="$remote_output_base/$rel_path"
        if ! mkdir -p "$dest_dir" 2>/tmp/nas_mkdir_error.log; then
            {
                echo "[ERROR] mkdir failed: $dest_dir"
                cat /tmp/nas_mkdir_error.log 2>/dev/null
            } >> "$nas_error_log"
            echo $(( $(cat "$nas_counter_failed") + 1 )) > "$nas_counter_failed"
            continue
        fi

        # cloth_input.txt がないディレクトリはシムの直接出力先ではない
        # （run-simulation.sh の rm -rf environment が失敗して environment が
        #   残っている場合に親ディレクトリを誤って処理するのを防ぐ）
        if [[ ! -f "$sim_dir/cloth_input.txt" ]]; then
            continue
        fi

        # environment ディレクトリが残っていても強制削除してから転送
        rm -rf "$sim_dir/environment" 2>/dev/null || true

        if rsync -a --exclude='environment' "$sim_dir/" "$dest_dir/" 2>/tmp/nas_transfer_error.log; then
            rm -rf "$sim_dir"
            mkdir -p "$sim_dir"
            echo "$progress" > "$sim_dir/progress.tmp"
            echo "$dest_dir" > "$sim_dir/.moved_to_remote"
            echo $(( $(cat "$nas_counter_transferred") + 1 )) > "$nas_counter_transferred"
        else
            {
                echo "[ERROR] rsync failed: $sim_dir -> $dest_dir"
                cat /tmp/nas_transfer_error.log 2>/dev/null
            } >> "$nas_error_log"
            echo $(( $(cat "$nas_counter_failed") + 1 )) > "$nas_counter_failed"
        fi
    done
}


# ---------------------------------------------------------------------------
# NAS転送を進捗表示から分離する独立ドレイナ。完了 sim を定期的にNASへ転送し、
# done==total で自己終了する (main の `wait` が回収する)。
# これにより表示ループは転送I/Oでブロックされず、一定間隔で再描画できる。
# ---------------------------------------------------------------------------
function nas_drainer() {
    if [[ -z "$remote_output_base" ]] || [ "$total_simulations" -eq 0 ]; then
        return 0
    fi
    local n_done=0 f v
    while [ "$n_done" -lt "$total_simulations" ]; do
        move_completed_to_remote
        n_done=0
        while IFS= read -r f; do
            [ -r "$f" ] || continue
            v=$(<"$f")
            if [ "$v" = "1" ] || [ "$v" = "failed" ]; then
                n_done=$((n_done + 1))
            fi
        done < <(find "$output_base" -type f -name "progress.tmp" ! -path "*/environment/*" 2>/dev/null)
        sleep 2
    done
    move_completed_to_remote   # 最終ドレイン (ループ終了直前に完了した分を確実に送る)
}


# ---------------------------------------------------------------------------
function enqueue_simulation() {
    queue+=("$@")
    ((total_simulations++))
}

function process_queue() {
    while [ "$running_processes" -lt "$max_processes" ] && [ "${#queue[@]}" -gt 0 ]; do
        eval "${queue[0]}" > /dev/null 2>&1 &
        queue=("${queue[@]:1}")
        ((running_processes++))
    done

    if [ "$running_processes" -gt 0 ]; then
        wait -n || true
        ((running_processes--))
    fi
}

function display_progress() {
    if [ "$total_simulations" -eq 0 ]; then
        return 0
    fi

    local n_done=0
    local n_failed=0
    last_lines=0   # 多行インプレース描画で前回出力した行数(カーソル巻き戻し用)

    # NAS転送は nas_drainer に分離済み。ここは「読むだけ」の軽量ループで 0.1s ごとに
    # その瞬間の状態を再描画する (8ce7590 の設定。cb27298 で意図せず 0.5s に戻っていた)。
    # python3/bc/ファイル毎 cat を排し bash 組み込み(+整数演算)に置換したので、
    # CPU飽和下でもほぼ 0.1s 刻みで更新が回る。
    while [ "$n_done" -lt "$total_simulations" ]; do
        mapfile -t simulation_progress_files < <(find "$output_base" -type f -name "progress.tmp" ! -path "*/environment/*" 2>/dev/null)

        n_done=0
        n_failed=0
        running_entries=()   # 実行中シミュレーション "progress|rel_path" を収集
        local file progress sim_dir rel_path
        for file in "${simulation_progress_files[@]}"; do
            [ -r "$file" ] || continue          # nas_drainer の rm/mkdir と競合した瞬間はスキップ
            progress=$(<"$file")                # fork無し読み取り
            if [ "$progress" = "1" ]; then
                n_done=$((n_done + 1))
            elif [ "$progress" = "failed" ]; then
                n_done=$((n_done + 1))
                n_failed=$((n_failed + 1))
            elif [[ "$progress" =~ ^[0-9]*\.?[0-9]+$ ]]; then
                # 実行中 (0<=progress<1): 進捗と出力先(相対パス)を保持
                sim_dir="${file%/progress.tmp}"
                rel_path="${sim_dir#$output_base/}"
                running_entries+=("$progress|$rel_path")
            fi
        done

        # NASカウンタ (fork無しで読む)
        local nas_ok=0 nas_ng=0
        [ -r "$nas_counter_transferred" ] && nas_ok=$(<"$nas_counter_transferred")
        [ -r "$nas_counter_failed" ]      && nas_ng=$(<"$nas_counter_failed")

        # 進捗％・バー・ETA を整数演算で算出 (python3/bc 不使用)
        local permille pct_int pct_dec filled bar progress_line
        permille=$(( n_done * 1000 / total_simulations ))
        pct_int=$(( permille / 10 ))
        pct_dec=$(( permille % 10 ))
        filled=$(( permille * 50 / 1000 ))
        bar=""
        if [ "$filled" -gt 0 ]; then
            printf -v bar '%*s' "$filled" ''
            bar="${bar// /#}"
        fi

        if [ "$n_done" -eq 0 ]; then
            printf -v progress_line "Progress: [%-50s] 0%%\t%d/%d\t Failed %d\t Time remaining --:--:--\t NAS: %s transferred / %s failed" "" "$n_done" "$total_simulations" "$n_failed" "$nas_ok" "$nas_ng"
        else
            local now elapsed remaining_time_sec r_h r_m r_s
            now=$(date +%s)
            elapsed=$(( now - start_time ))
            remaining_time_sec=$(( elapsed * (total_simulations - n_done) / n_done ))
            [ "$remaining_time_sec" -lt 0 ] && remaining_time_sec=0
            r_h=$(( remaining_time_sec / 3600 ))
            r_m=$(( (remaining_time_sec % 3600) / 60 ))
            r_s=$(( remaining_time_sec % 60 ))
            printf -v progress_line "Progress: [%-50s] %d.%d%%\t%d/%d\t Failed %d\t Time remaining %02d:%02d:%02d\t NAS: %s transferred / %s failed" "$bar" "$pct_int" "$pct_dec" "$n_done" "$total_simulations" "$n_failed" "$r_h" "$r_m" "$r_s" "$nas_ok" "$nas_ng"
        fi

        # --- 実行中シミュレーションの進捗行 (進捗降順, 最大12行) ---
        local running_block="" n_running_shown=0
        if [ "${#running_entries[@]}" -gt 0 ]; then
            n_running_shown=$(( ${#running_entries[@]} > 12 ? 12 : ${#running_entries[@]} ))
            running_block=$(printf '%s\n' "${running_entries[@]}" | sort -t'|' -k1 -rn | head -12 | awk -F'|' '{ printf "    [%6.1f%%] %s\n", $1*100, $2 }')
            running_block+=$'\n'   # command-sub が剥がした最終改行を補填し旧描画と行数を一致させる
        fi

        # --- 多行インプレース描画: 前回ブロックをカーソル巻き戻し+消去して再描画 ---
        if [ "$last_lines" -gt 0 ]; then
            printf "\033[%dA\r\033[J" "$last_lines"
        fi
        printf "%s\n" "$progress_line"
        printf "%s" "$running_block"
        last_lines=$((1 + n_running_shown))
        sleep 0.1
    done
    # 最後のブロックを消去してメイン進捗行のみ確定表示
    if [ "$last_lines" -gt 0 ]; then
        printf "\033[%dA\r\033[J" "$last_lines"
    fi
    printf "%s\n" "$progress_line"
}

# ---------------------------------------------------------------------------
# Display configuration
# ---------------------------------------------------------------------------
echo "=========================================="
echo "監視ノード数スイープシミュレーション（並列実行）"
echo "=========================================="
echo ""
echo "固定パラメータ:"
echo "  攻撃ノード割合: $MALICIOUS_RATIO"
echo "  攻撃成功率    : $ATTACK_SUCCESS_RATE"
echo ""
echo "スイープパラメータ:"
echo "  取引回数       : ${N_PAYMENTS[*]}"
echo "  平均支払額（msat） : ${PAYMENT_AMOUNTS[*]}"
echo "  監視ノード数   : ${MONITOR_NODE_COUNTS[*]}"
echo "  監視方法       : ${MONITORING_METHODS[*]}"
echo "  防御モード     : method固定対応 (disable→no_defense, method1/2→avoid_low_reputation)"
echo "  p値（閾値）    : ${P_VALUES[*]}"
echo ""
p_combo_count=$(( ${#P_VALUES[@]} > 0 ? ${#P_VALUES[@]} : 1 ))
echo ""
disable_method_count=0
enabled_method_count=0
for method in "${MONITORING_METHODS[@]}"; do
    if [[ "$method" == "monitor_disable" ]]; then
        ((disable_method_count++))
    else
        ((enabled_method_count++))
    fi
done
n_disable_combos=$(( disable_method_count * 1 * p_combo_count ))
n_method_combos=$(( enabled_method_count * ${#MONITOR_NODE_COUNTS[@]} * 1 * p_combo_count ))
n_combinations=$(( ${#N_PAYMENTS[@]} * ${#PAYMENT_AMOUNTS[@]} * (n_disable_combos + n_method_combos) ))
n_total_sims=$n_combinations
echo "  監視無効パターン        : $n_disable_combos"
echo "  監視有効パターン        : $n_method_combos"
echo "  計測パターン合計         :$(( n_disable_combos + n_method_combos ))"
echo ""
echo "  組み合わせ数            : $n_combinations"
echo "  合計シミュレーション数  : $n_total_sims"
echo "  並列プロセス数          : $max_processes"
echo "  シード値                : $seed_base"
echo "  タイムスタンプ          : $timestamp"
echo ""
echo "出力先: $output_base"
echo "=========================================="
echo ""

# ---------------------------------------------------------------------------
# Enqueue simulations
# ---------------------------------------------------------------------------
for n_payment in "${N_PAYMENTS[@]}"; do
    for avg_pmt in "${PAYMENT_AMOUNTS[@]}"; do
        var_pmt=$((avg_pmt / 10))
            for method in "${MONITORING_METHODS[@]}"; do

                # Pair no_defense with monitoring disabled, and defense with monitoring enabled
                # 代役ハブenv: baseline(disable)には付けず、防御2モード(method1/2)にのみ付ける。
                sub_env=""
                case "$method" in
                    monitor_disable)
                        strategy_val="disabled"
                        monitor_counts_iter=(0)
                        defense_modes_iter=(no_defense)
                        # baseline=対照。代役なし。空代入 CLOTH_SUBSTITUTE_COUNT= で、
                        # ユーザシェルが誤ってグローバル export していても遮蔽する
                        # (cloth.c は空文字列を 0=OFF として扱う)。
                        sub_env="CLOTH_SUBSTITUTE_COUNT="
                        ;;
                    monitor_method1)
                        strategy_val="method1"
                        monitor_counts_iter=("${MONITOR_NODE_COUNTS[@]}")
                        defense_modes_iter=(avoid_low_reputation)
                        sub_env="$SUB_ENV_DEFENSE $DETECT_ENV_DEFENSE"       # 防御モードに代役+per-node null(各々有効時のみ非空)
                        ;;
                    monitor_method2)
                        strategy_val="method2"
                        monitor_counts_iter=("${MONITOR_NODE_COUNTS[@]}")
                        defense_modes_iter=(avoid_low_reputation)
                        sub_env="$SUB_ENV_DEFENSE $DETECT_ENV_DEFENSE"       # 防御モードに代役+per-node null(各々有効時のみ非空)
                        ;;
                    *)
                        echo "ERROR: Unknown monitoring method: $method"
                        exit 1
                    ;;
            esac

            for defense in "${defense_modes_iter[@]}"; do
                # NOTE: 旧 avoid_low_reputation=/enable_reputation_system= 引数は削除した。
                # 前者は C 側に消費者が存在しない完全な no-op、後者は cloth.c が
                # monitoring_strategy から正規化するため必ず上書きされる死んだノブだった。
                # 防御切替の実体は monitoring_strategy + enable_rbr + enable_prt の3つ。
                if [[ "$defense" == "no_defense" ]]; then
                    enable_rbr_val="false"
                    enable_prt_val="false"   # 対照(no_defense)は素のタイムアウト挙動=PRT-off
                else
                    enable_rbr_val="true"
                    enable_prt_val="true"    # 防御は早期打ち切り(PRT)を含む
                fi

                for monitor_count in "${monitor_counts_iter[@]}"; do
                    if [[ "$method" == "monitor_disable" ]]; then
                        output_dir="$output_base/$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt"
                    else
                        output_dir="$output_base/$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt/monitor_count=$monitor_count"
                    fi

                    # Build base command for this configuration (per-p variation handled below)
base_cmd_args="n_additional_nodes=$NODE_SCALES \
                        n_payments=$n_payment \
                        mpp=0 payment_timeout=200000 \
                        malicious_node_ratio=$MALICIOUS_RATIO malicious_failure_probability=$ATTACK_SUCCESS_RATE \
                        monitoring_strategy=$strategy_val \
                        top_hub_count=$TOP_HUB_COUNT \
                        monitor_node_limit=$monitor_count \
                        enable_monitor_movement=false movement_credit_limit=0 \
                        enable_pra=false enable_prt=$enable_prt_val enable_rbr=$enable_rbr_val \
                        average_payment_amount=$avg_pmt variance_payment_amount=$var_pmt \
                        $ATTACK_DELAY_PARAMS_ON"

# If P_VALUES provided, enqueue one simulation per p-value (set env var and add p subdir)
if [ ${#P_VALUES[@]} -gt 0 ]; then
    for p in "${P_VALUES[@]}"; do
        pdir="p_${p//./_}"
        outdir_p="$output_dir/$pdir"
        # Ensure output dir exists when simulation runs
        mkdir -p "$outdir_p"
        # run-simulation.sh は絶対パスで参照する。旧 ./run-simulation.sh は repo root 以外
        # から起動すると全 eval が静かに失敗し progress.tmp が永久に書かれずハングしていた。
        cmd="$sub_env CLOTH_PVALUE_THRESHOLD=$p \"$project_root/run-simulation.sh\" $seed_base $outdir_p $base_cmd_args"
        enqueue_simulation "$cmd"
    done
else
    mkdir -p "$output_dir"
    cmd="$sub_env \"$project_root/run-simulation.sh\" $seed_base $output_dir $base_cmd_args"
    enqueue_simulation "$cmd"
fi
                done
            done
        done
    done
done
# Debug: Print first queue item
if [ ${#queue[@]} -gt 0 ]; then
    echo "[DEBUG] First queue item (truncated):"
    echo "  ${queue[0]}" | head -c 200
    echo "..."
    echo ""
fi

# ---------------------------------------------------------------------------
# Run queue with parallel execution
# ---------------------------------------------------------------------------
running_processes=0
start_time=$(date +%s)

display_progress &
nas_drainer &
while [ "${#queue[@]}" -gt 0 ] || [ "$running_processes" -gt 0 ]; do
    process_queue
    sleep 1
done
wait
printf "\n"
move_completed_to_remote

# 進捗表示中に蓄積されたNAS転送エラーをまとめて表示し、カウンタ一時ファイルを掃除する。
# (旧 display_progress 末尾から移設: 表示と転送を分離したので、両 background が `wait` で
#  終了しきった後=ここが正しい後始末位置。display_progress 走行中にカウンタを消さない)
if [[ -s "$nas_error_log" ]]; then
    echo ""
    echo "=== NAS転送エラー詳細 ==="
    cat "$nas_error_log"
    echo "========================="
fi
rm -f "$nas_error_log" "$nas_counter_transferred" "$nas_counter_failed"

echo ""
echo "=========================================="
echo "全シミュレーション完了"
echo "出力先: $output_base"
if [[ -n "$remote_output_base" ]]; then
    echo "リモート出力先: $remote_output_base"
fi
echo "=========================================="

# ---------------------------------------------------------------------------
# results_summary.csv 生成 (生成ロジックは上部 generate_summary_csv 関数に集約)
# ---------------------------------------------------------------------------
generate_summary_csv

# ---------------------------------------------------------------------------
# Timing summary
# ---------------------------------------------------------------------------
end_time=$(date +%s)
echo ""
echo "START : $(date -r "$start_time" "+%Y-%m-%d %H:%M:%S")"
echo "  END : $(date -r "$end_time" "+%Y-%m-%d %H:%M:%S")"
elapsed=$((end_time - start_time))
hours=$((elapsed / 3600))
minutes=$(( (elapsed % 3600) / 60 ))
seconds=$((elapsed % 60))
echo " TIME : $(printf "%02d:%02d:%02d" $hours $minutes $seconds)"
