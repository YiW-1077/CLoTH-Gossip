#!/opt/homebrew/bin/bash
# 監視ノード数スイープシミュレーション（並列実行）
# run_all_simulations_change_groupparams.sh に倣い、
# 監視ノード数 (monitor_node_limit) をスイープ変数として
# a〜e の5シナリオを各組み合わせで実行する。
# Usage: ./run_monitor_sweep.sh <seed> <output_base_dir> [remote_output_dir_or_smb_uri] [key=value ...]
# Example: ./run_monitor_sweep.sh 42 /output/dir monitoring_strategy=method1

if [ $# -lt 2 ]; then
    echo "Usage: $0 <seed> <output_base_dir> [remote_output_dir_or_smb_uri] [key=value ...]"
    echo "Example: $0 42 /output/dir monitoring_strategy=method1"
    exit 1
fi

seed_base="$1"
output_base_arg="$2"
remote_arg="${3:-${REMOTE_OUTPUT_DIR:-}}"
project_root="$(cd "$(dirname "$0")" && pwd)"

# Process additional keyword arguments for monitoring_strategy override
MONITORING_METHODS_OVERRIDE=""
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
    if [[ "$arg" == defense_mode=* ]]; then
        def_value="${arg#defense_mode=}"
        case "$def_value" in
            none|no_defense|off)
                DEFENSE_MODE_OVERRIDE="no_defense"
                ;;
            avoid_low_reputation|avoid_reputation|avoid)
                DEFENSE_MODE_OVERRIDE="avoid_low_reputation"
                ;;
            all)
                DEFENSE_MODE_OVERRIDE="no_defense avoid_low_reputation"
                ;;
            *)
                echo "ERROR: Invalid defense_mode: $def_value"
                echo "Valid options: none,no_defense,avoid_low_reputation,all"
                exit 1
                ;;
        esac
        echo "[Config] Override DEFENSE_MODES: $DEFENSE_MODE_OVERRIDE"
    fi
done

# Create timestamped output directory (always local)
timestamp=$(date "+%Y%m%d%H%M%S")

# ---------------------------------------------------------------------------
# Fixed parameters
# ---------------------------------------------------------------------------
N_PAYMENTS=(100 300 500 800 1000 1500 2000 2700 3500 4500)
MALICIOUS_RATIO=0.15
ATTACK_SUCCESS_RATE=0.80
TOP_HUB_COUNT=10

ATTACK_DELAY_PARAMS_ON="enable_network_attack_delay=true  attack_delay_start_time=3000 attack_delay_duration=30000 attack_delay_intensity=2.0 attack_delay_jitter=0.0"

# ---------------------------------------------------------------------------
# Sweep parameters
# ---------------------------------------------------------------------------
NODE_SCALES=6000
PAYMENT_AMOUNTS=(1000 5000 10000)

# 監視ノード数の絶対数リスト
MONITOR_NODE_COUNTS=(10 50 100 300 500)
MONITORING_METHODS=(monitor_disable monitor_method1 monitor_method2)

# Defense modes: compare with and without avoiding low-reputation nodes
DEFENSE_MODES=(no_defense avoid_low_reputation)
DEFENSE_MODE_OVERRIDE=""

# Apply MONITORING_METHODS override if specified
if [[ -n "$MONITORING_METHODS_OVERRIDE" ]]; then
    MONITORING_METHODS=($MONITORING_METHODS_OVERRIDE)
fi

# Apply DEFENSE_MODES override if specified
if [[ -n "$DEFENSE_MODE_OVERRIDE" ]]; then
    DEFENSE_MODES=($DEFENSE_MODE_OVERRIDE)
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
    if [[ "$remote_arg" == smb://172.20.86.110/public1/* ]]; then
        mount_path="/Volumes/public1"

        if ! mount | grep -q "on $mount_path"; then
            echo "NAS not mounted. Attempting to mount..."
            echo "[DEBUG] Mount path: $mount_path"
            echo "[DEBUG] Current mounts:"
            mount | grep -E "public1|smbfs" || echo "[DEBUG] No SMB mounts found"

            mkdir -p "$mount_path" 2>/dev/null || {
                echo "[ERROR] Cannot create mount directory: $mount_path"
                remote_arg=""
            }

            if [[ -n "$remote_arg" ]]; then
                echo "[DEBUG] Created/verified mount directory: $mount_path"
                ls -ld "$mount_path" 2>/dev/null || true

                echo "[DEBUG] Attempt 1: Mounting without credentials..."
                if mount_smbfs "//morinolab@172.20.86.110/public1" "$mount_path" 2>/tmp/mount_debug.log; then
                    echo "[DEBUG] Mount successful!"
                else
                    mount_error=$(cat /tmp/mount_debug.log 2>/dev/null || echo "Unknown error")
                    echo "[DEBUG] Mount failed (attempt 1): $mount_error"

                    echo "[DEBUG] Attempt 2: Mounting with credentials..."
                    if [[ -n "$SMB_PASSWORD" ]]; then
                        smbpass="$SMB_PASSWORD"
                        echo "[DEBUG] Using SMB_PASSWORD environment variable"
                    else
                        read -sp "Enter SMB password for morinolab: " smbpass
                        echo ""
                    fi

                    smbpass_escaped=$(echo "$smbpass" | sed 's/[&/\]/\\&/g')

                    if mount_smbfs "//morinolab:${smbpass_escaped}@172.20.86.110/public1" "$mount_path" 2>/tmp/mount_debug2.log; then
                        echo "[DEBUG] Mount successful with credentials!"
                    else
                        mount_error=$(cat /tmp/mount_debug2.log 2>/dev/null || echo "Unknown error")
                        echo "[ERROR] Cannot mount NAS at $mount_path"
                        echo "[DEBUG] Mount error: $mount_error"
                        echo ""
                        echo "[DEBUG] Network diagnostics:"
                        ping -c 1 172.20.86.110 2>/dev/null && echo "  ✓ Host 172.20.86.110 is reachable" || echo "  ✗ Host 172.20.86.110 is NOT reachable"
                        echo ""
                        echo "      To mount manually, run:"
                        echo "      mount_smbfs '//morinolab:PASSWORD@172.20.86.110/public1' '$mount_path'"
                        echo ""
                        echo "      Or set SMB_PASSWORD environment variable:"
                        echo "      export SMB_PASSWORD='your_password'"
                        echo "      ./run_monitor_sweep.sh <seed> <output_dir> <remote_path>"
                        remote_arg=""
                        rm -f /tmp/mount_debug.log /tmp/mount_debug2.log
                    fi
                fi
            fi
        fi

        if [[ -n "$remote_arg" ]]; then
            remote_arg="/Volumes/public1/${remote_arg#smb://172.20.86.110/public1/}"
        fi
    elif [[ "$remote_arg" == smb://* ]]; then
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

    done_simulations=0
    failed_simulations=0

    while [ "$done_simulations" -lt "$total_simulations" ]; do
        move_completed_to_remote
        mapfile -t simulation_progress_files < <(find "$output_base" -type f -name "progress.tmp" ! -path "*/environment/*" 2>/dev/null)

        done_simulations=0
        failed_simulations=0
        for file in "${simulation_progress_files[@]}"; do
            progress=$(cat "$file" 2>/dev/null || echo "0")
            if [ "$progress" = "1" ] || [ "$progress" = "failed" ]; then
                done_simulations=$((done_simulations + 1))
            fi
            if [ "$progress" = "failed" ]; then
                failed_simulations=$((failed_simulations + 1))
            fi
        done

        if [ "$total_simulations" -eq 0 ]; then
            fraction=0
        else
            fraction=$(echo "scale=4; $done_simulations / $total_simulations" | bc)
        fi

        filled=$(printf "%.0f" "$(echo "$fraction * 50" | bc)")
        progress_bar=$(printf "%0.s#" $(seq 1 "$filled"))

        # NASカウンタをファイルから読み出してから進捗行に埋め込む
        nas_ok=$(cat "$nas_counter_transferred" 2>/dev/null || echo 0)
        nas_ng=$(cat "$nas_counter_failed"      2>/dev/null || echo 0)

        if [ "$(python3 -c "print(float('$fraction')==0.0)" 2>/dev/null)" = "True" ]; then
            progress_line=$(printf "Progress: [%-50s] 0%%\t%d/%d\t Failed %d\t Time remaining --:--:--\t NAS: %d transferred / %d failed" "" "$done_simulations" "$total_simulations" "$failed_simulations" "$nas_ok" "$nas_ng")
        else
            elapsed_time=$(( $(date +%s) - start_time ))
            remaining_time_sec=$(python3 -c "f=float('$fraction'); elapsed=$elapsed_time; est=int(elapsed / f - elapsed); print(max(0, est))" 2>/dev/null || echo "0")
            remaining_hours=$(( remaining_time_sec / 3600 ))
            remaining_minutes=$(( (remaining_time_sec % 3600) / 60 ))
            remaining_seconds=$(( remaining_time_sec % 60 ))
            percent=$(echo "scale=1; $fraction * 100" | bc)
            progress_line=$(printf "Progress: [%-50s] %s%%\t%d/%d\t Failed %d\t Time remaining %02d:%02d:%02d\t NAS: %d transferred / %d failed" "$progress_bar" "$percent" "$done_simulations" "$total_simulations" "$failed_simulations" "$remaining_hours" "$remaining_minutes" "$remaining_seconds" "$nas_ok" "$nas_ng")
        fi

        printf "\r\033[2K%s" "$progress_line"
        sleep 1
    done
    printf "\n"
    # 進捗表示中に蓄積されたNASエラーがあればまとめて表示
    if [[ -s "$nas_error_log" ]]; then
        echo ""
        echo "=== NAS転送エラー詳細 ==="
        cat "$nas_error_log"
        echo "========================="
    fi
    rm -f "$nas_error_log" "$nas_counter_transferred" "$nas_counter_failed"
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
echo "  監視ノード数       : ${MONITOR_NODE_COUNTS[*]}"
echo "  平均支払額（msat） : ${PAYMENT_AMOUNTS[*]}"
echo "  監視方法       : ${MONITORING_METHODS[*]}"
echo "  防御モード     : ${DEFENSE_MODES[*]}"
echo ""
echo "シナリオ: detection_only（攻撃あり・検知のみ）"
echo ""
n_combinations=$(( ${#N_PAYMENTS[@]} * ${#MONITOR_NODE_COUNTS[@]} * ${#PAYMENT_AMOUNTS[@]} * ${#MONITORING_METHODS[@]} * ${#DEFENSE_MODES[@]} ))
n_total_sims=$n_combinations
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

            # Determine strategy and reputation values based on method
            case "$method" in
                monitor_disable)
                    strategy_val="disabled"
                    enable_rep_val="false"
                    monitor_counts_iter=(0)
                    ;;
                monitor_method1)
                    strategy_val="method1"
                    enable_rep_val="true"
                    monitor_counts_iter=("${MONITOR_NODE_COUNTS[@]}")
                    ;;
                monitor_method2)
                    strategy_val="method2"
                    enable_rep_val="true"
                    monitor_counts_iter=("${MONITOR_NODE_COUNTS[@]}")
                    ;;
                *)
                    echo "ERROR: Unknown monitoring method: $method"
                    exit 1
                    ;;
            esac

            for defense in "${DEFENSE_MODES[@]}"; do
                if [[ "$defense" == "no_defense" ]]; then
                    avoid_low_rep_val="false"
                    enable_rep_system_val="$enable_rep_val"
                    enable_rbr_val="false"
                else
                    avoid_low_rep_val="true"
                    enable_rep_system_val="true"
                    enable_rbr_val="true"
                fi

                for monitor_count in "${monitor_counts_iter[@]}"; do
                    if [[ "$method" == "monitor_disable" ]]; then
                        output_dir="$output_base/$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt"
                    else
                        output_dir="$output_base/$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt/monitor_count=$monitor_count"
                    fi

                    enqueue_simulation "./run-simulation.sh $seed_base $output_dir \
                        n_additional_nodes=$NODE_SCALES \
                        n_payments=$n_payment \
                        mpp=0 payment_timeout=200000 \
                        malicious_node_ratio=$MALICIOUS_RATIO malicious_failure_probability=$ATTACK_SUCCESS_RATE \
                        monitoring_strategy=$strategy_val \
                        top_hub_count=$TOP_HUB_COUNT \
                        monitor_node_limit=$monitor_count \
                        enable_reputation_system=$enable_rep_system_val \
                        avoid_low_reputation=$avoid_low_rep_val \
                        enable_monitor_movement=false movement_credit_limit=0 \
                        enable_pra=false enable_prt=false enable_rbr=$enable_rbr_val \
                        average_payment_amount=$avg_pmt variance_payment_amount=$var_pmt \
                        $ATTACK_DELAY_PARAMS_ON"
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
while [ "${#queue[@]}" -gt 0 ] || [ "$running_processes" -gt 0 ]; do
    process_queue
    sleep 1
done
wait
printf "\n"
move_completed_to_remote

echo ""
echo "=========================================="
echo "全シミュレーション完了"
echo "出力先: $output_base"
if [[ -n "$remote_output_base" ]]; then
    echo "リモート出力先: $remote_output_base"
fi
echo "=========================================="

# ---------------------------------------------------------------------------
# Generate results_summary.csv
#   監視ノード数 (monitor_count) ごとの検出率変化を中心にまとめる。
#
# 取得元:
#   baseline_metrics.csv (列固定, ヘッダ1行+データ1行)
#     col1 : n_payments
#     col2 : n_successful
#     col3 : n_failed
#     col4 : success_rate
#     col5 : avg_delay
#     col6 : malicious_ratio
#     col7 : malicious_prob
#     col8 : total_attacks_triggered
#     col9 : attack_delay_total
#     col10: attack_delay_avg_per_payment
#     col11: payments_with_attack_delay
#     col12: attack_delay_events
#     col13: total_malicious_nodes
#     col14: detection_rate          ← rbr_detected / detected_malicious
#     col15: rbr_detected_nodes
#
#   summary.csv (key=value 形式)
#     total_malicious_nodes
#     malicious_detection_rate_percent  ← detected_malicious / total_malicious * 100
#     num_monitors
#     monitoring_coverage_rate_percent
#     payment_success_rate_percent
# ---------------------------------------------------------------------------
csv_output="$output_base/results_summary.csv"
echo "Generating CSV summary: $csv_output"
echo ""

# summary.csv から指定キーの値を取り出すヘルパー関数
function get_summary_value() {
    local file="$1"
    local key="$2"
    grep "^${key}," "$file" 2>/dev/null | cut -d',' -f2 | tr -d '[:space:]' || echo "N/A"
}

{
    # ヘッダ（defense_mode を追加）
     echo "node_count,payment_amount_msat,monitor_node_count,defense_mode,status,monitor_method,n_payments,n_successful,n_failed,success_rate_raw,payment_success_rate_pct,total_attacks_triggered,total_malicious_nodes,malicious_detection_rate_pct,rbr_detected_nodes,rbr_over_detected_rate,avg_delay,total_attacks_triggered,monitoring_coverage_rate_pct,num_monitors_actual"

     for n_payment in "${N_PAYMENTS[@]}"; do
         for avg_pmt in "${PAYMENT_AMOUNTS[@]}"; do
             for method in "${MONITORING_METHODS[@]}"; do
                 if [[ "$method" == "monitor_disable" ]]; then
                     monitor_counts_csv=(0)
                 else
                     monitor_counts_csv=("${MONITOR_NODE_COUNTS[@]}")
                 fi
                 for monitor_count in "${monitor_counts_csv[@]}"; do
                     # 各防御モードの存在を確認して出力（両方あれば両方出力）
                     def_options=(no_defense avoid_low_reputation)
                     defenses_found=()
                     for d in "${def_options[@]}"; do
                         if [[ "$method" == "monitor_disable" ]]; then
                             check_dir="$remote_output_base/$d/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt"
                         else
                             check_dir="$remote_output_base/$d/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt/monitor_count=$monitor_count"
                         fi
                         if [[ -d "$check_dir" ]]; then
                             defenses_found+=("$d")
                         fi
                     done

                     # 見つからなければ旧来のパスを使う（防御無し扱い／unknown 表示）
                     if [ ${#defenses_found[@]} -eq 0 ]; then
                         if [[ "$method" == "monitor_disable" ]]; then
                             sim_dir="$remote_output_base/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt"
                         else
                             sim_dir="$remote_output_base/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt/monitor_count=$monitor_count"
                         fi
                         defenses_found=("unknown")
                     fi

                     for defense in "${defenses_found[@]}"; do
                         if [[ "$defense" == "unknown" ]]; then
                             # sim_dir already set above
                             :
                         else
                             if [[ "$method" == "monitor_disable" ]]; then
                                 sim_dir="$remote_output_base/$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt"
                             else
                                 sim_dir="$remote_output_base/$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt/monitor_count=$monitor_count"
                             fi
                         fi

                         # --- ステータス判定 ---
                         status="PENDING"
                         if [ -f "$sim_dir/progress.tmp" ]; then
                             progress=$(cat "$sim_dir/progress.tmp" 2>/dev/null || echo "0")
                             if   [ "$progress" = "1" ];      then status="OK"
                             elif [ "$progress" = "failed" ]; then status="FAILED"
                             else                                   status="RUNNING"
                             fi
                         fi

                         # --- baseline_metrics.csv から取得 ---
                         n_payments="N/A"
                         n_successful="N/A"
                         n_failed="N/A"
                         success_rate_raw="N/A"
                         avg_delay="N/A"
                         total_attacks_triggered="N/A"
                         total_malicious_nodes="N/A"
                         rbr_over_detected_rate="N/A"
                         rbr_detected_nodes="N/A"

                         bm="$sim_dir/baseline_metrics.csv"
                         if [ -f "$bm" ]; then
                             data_line=$(tail -1 "$bm")
                             n_payments=$(echo "$data_line"            | cut -d',' -f1)
                             n_successful=$(echo "$data_line"          | cut -d',' -f2)
                             n_failed=$(echo "$data_line"              | cut -d',' -f3)
                             success_rate_raw=$(echo "$data_line"      | cut -d',' -f4)
                             avg_delay=$(echo "$data_line"             | cut -d',' -f5)
                             total_attacks_triggered=$(echo "$data_line" | cut -d',' -f8)
                             total_malicious_nodes=$(echo "$data_line" | cut -d',' -f13)
                             rbr_over_detected_rate=$(echo "$data_line"   | cut -d',' -f14)
                             rbr_detected_nodes=$(echo "$data_line"       | cut -d',' -f15)
                         fi

                         # --- summary.csv から取得 (key=value 形式) ---
                         total_malicious_nodes="N/A"
                         malicious_detection_rate_pct="N/A"
                         payment_success_rate_pct="N/A"
                         monitoring_coverage_rate_pct="N/A"
                         num_monitors_actual="N/A"

                         sm="$sim_dir/summary.csv"
                         if [ -f "$sm" ]; then
                             total_malicious_nodes=$(get_summary_value "$sm" "total_malicious_nodes")
                             malicious_detection_rate_pct=$(get_summary_value "$sm" "malicious_detection_rate_percent")
                             payment_success_rate_pct=$(get_summary_value "$sm" "payment_success_rate_percent")
                             monitoring_coverage_rate_pct=$(get_summary_value "$sm" "monitoring_coverage_rate_percent")
                             num_monitors_actual=$(get_summary_value "$sm" "num_monitors")
                         fi

                         echo "$NODE_SCALES,$avg_pmt,$monitor_count,$defense,$status,$method,\
                               $n_payments,$n_successful,$n_failed,\
                               $success_rate_raw,$payment_success_rate_pct,\
                               $total_attacks_triggered,$total_malicious_nodes,\
                               $malicious_detection_rate_pct,\
                               $rbr_detected_nodes,$rbr_over_detected_rate,\
                               $avg_delay,$total_attacks_triggered,\
                               $monitoring_coverage_rate_pct,$num_monitors_actual"
                     done  # defense entries
                 done  # monitor_count
             done  # method
         done  # avg_pmt
     done  # n_payment

} > "$csv_output"

echo "Summary CSV: $csv_output"

# Transfer summary CSV to NAS
if [[ -n "$remote_output_base" ]]; then
    if mkdir -p "$remote_output_base" 2>/tmp/nas_final_error.log; then
        if cp "$csv_output" "$remote_output_base/results_summary.csv" 2>/tmp/nas_csv_error.log; then
            echo "✓ Summary CSV transferred to NAS"
        else
            echo "[ERROR] Failed to transfer summary CSV:"
            cat /tmp/nas_csv_error.log 2>/dev/null || echo "No error details"
        fi
    else
        echo "[ERROR] Failed to create final NAS directory: $remote_output_base"
        cat /tmp/nas_final_error.log 2>/dev/null || echo "No error details"
    fi
fi

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
