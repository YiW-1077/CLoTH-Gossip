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
N_PAYMENTS=(200 400 800 1600 3200 6400 12800)
MALICIOUS_RATIO=0.15
ATTACK_SUCCESS_RATE=1.0
TOP_HUB_COUNT=10

ATTACK_DELAY_PARAMS_ON="enable_network_attack_delay=true  attack_delay_start_time=3000 attack_delay_duration=30000 attack_delay_intensity=2.0 attack_delay_jitter=0.0"

# ---------------------------------------------------------------------------
# Sweep parameters
# ---------------------------------------------------------------------------
NODE_SCALES=6000
PAYMENT_AMOUNTS=(1000 5000 10000)

# 監視ノード数の絶対数リスト
MONITOR_NODE_COUNTS=(10 50)
MONITORING_METHODS=(monitor_disable monitor_method1 monitor_method2)

# Defense modes: compare with and without avoiding low-reputation nodes
DEFENSE_MODES=(no_defense avoid_low_reputation)
MONITOR_DISABLE_DEFENSE_MODES=(no_defense)
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
n_combinations=$(( ${#N_PAYMENTS[@]} * ${#PAYMENT_AMOUNTS[@]} * (1 * ${#MONITOR_DISABLE_DEFENSE_MODES[@]} + 2 * ${#MONITOR_NODE_COUNTS[@]} * ${#DEFENSE_MODES[@]}) ))
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
                        defense_modes_iter=("${MONITOR_DISABLE_DEFENSE_MODES[@]}")
                        ;;
                    monitor_method1)
                        strategy_val="method1"
                        enable_rep_val="true"
                        monitor_counts_iter=("${MONITOR_NODE_COUNTS[@]}")
                        defense_modes_iter=("${DEFENSE_MODES[@]}")
                        ;;
                    monitor_method2)
                        strategy_val="method2"
                        enable_rep_val="true"
                        monitor_counts_iter=("${MONITOR_NODE_COUNTS[@]}")
                        defense_modes_iter=("${DEFENSE_MODES[@]}")
                        ;;
                    *)
                        echo "ERROR: Unknown monitoring method: $method"
                        exit 1
                    ;;
            esac

            for defense in "${defense_modes_iter[@]}"; do
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

                    # Build base command for this configuration (per-p variation handled below)
base_cmd_args="n_additional_nodes=$NODE_SCALES \
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

# If P_VALUES provided, enqueue one simulation per p-value (set env var and add p subdir)
if [ ${#P_VALUES[@]} -gt 0 ]; then
    for p in "${P_VALUES[@]}"; do
        pdir="p_${p//./_}"
        outdir_p="$output_dir/$pdir"
        # Ensure output dir exists when simulation runs
        mkdir -p "$outdir_p"
        cmd="CLOTH_PVALUE_THRESHOLD=$p ./run-simulation.sh $seed_base $outdir_p $base_cmd_args"
        enqueue_simulation "$cmd"
    done
else
    mkdir -p "$output_dir"
    cmd="./run-simulation.sh $seed_base $output_dir $base_cmd_args"
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
# Generate results_summary.csv with improved format
# 改善されたフォーマット:
#   defense_strategy, monitor_method, payment_amount_sat, payment_amount_msat,
#   monitor_count, n_transactions, n_successful, n_failed,
#   success_rate_pct, avg_delay_ms, attacks_triggered, detection_rate_pct
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
    # 改善されたヘッダ
    echo "defense_strategy,monitor_method,p_value,payment_amount_sat,payment_amount_msat,monitor_count,n_transactions,n_successful,n_failed,success_rate_pct,avg_delay_ms,attacks_triggered,detection_rate_pct"

    for n_payment in "${N_PAYMENTS[@]}"; do
        for avg_pmt in "${PAYMENT_AMOUNTS[@]}"; do
            payment_msat=$((avg_pmt * 1000))  # Convert sat to msat
            
            for method in "${MONITORING_METHODS[@]}"; do
                if [[ "$method" == "monitor_disable" ]]; then
                    monitor_counts_csv=(0)
                else
                    monitor_counts_csv=("${MONITOR_NODE_COUNTS[@]}")
                fi
                
                for monitor_count in "${monitor_counts_csv[@]}"; do
                    # Determine per-method defense options
                    if [[ "$method" == "monitor_disable" ]]; then
                        def_options=("${MONITOR_DISABLE_DEFENSE_MODES[@]}")
                    else
                        def_options=("${DEFENSE_MODES[@]}")
                    fi

                    # Iterate over p-values; if none provided, use a single placeholder "N/A"
                    if [ ${#P_VALUES[@]} -gt 0 ]; then
                        p_iter=("${P_VALUES[@]}")
                    else
                        p_iter=("N/A")
                    fi

                    for p in "${p_iter[@]}"; do
                        # sanitize p for directory name
                        if [[ "$p" == "N/A" ]]; then
                            pdir=""
                        else
                            pdir="p_${p//./_}"
                        fi

                        for defense in "${def_options[@]}"; do
                            # Build relative path including pdir when present
                            if [[ "$method" == "monitor_disable" ]]; then
                                rel_path="$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt"
                            else
                                rel_path="$defense/$method/n_payment$n_payment/avg_pmt_amt=$avg_pmt/monitor_count=$monitor_count"
                            fi
                            if [[ -n "$pdir" ]]; then
                                rel_path="$rel_path/$pdir"
                            fi

                            # Try remote location first (NAS), then local
                            sim_dir=""
                            if [[ -n "$remote_output_base" ]]; then
                                if [[ -d "$remote_output_base/$rel_path" ]]; then
                                    sim_dir="$remote_output_base/$rel_path"
                                fi
                            fi
                            if [[ -z "$sim_dir" ]] && [[ -d "$output_base/$rel_path" ]]; then
                                sim_dir="$output_base/$rel_path"
                            fi

                            # Skip if directory not found
                            if [[ -z "$sim_dir" ]]; then
                                continue
                            fi

                            # --- 防御戦略の正規化 ---
                            defense_strategy="no_defense"
                            if [[ "$defense" == "avoid_low_reputation" ]]; then
                                defense_strategy="avoid_low_reputation"
                            fi

                            # --- 監視方法の正規化 ---
                            monitor_method_short="disable"
                            if [[ "$method" == "monitor_method1" ]]; then
                                monitor_method_short="method1"
                            elif [[ "$method" == "monitor_method2" ]]; then
                                monitor_method_short="method2"
                            fi

                            # --- summary.csv から取得 ---
                            n_transactions="N/A"
                            n_successful="N/A"
                            n_failed="N/A"
                            success_rate_pct="N/A"
                            avg_delay_ms="N/A"
                            attacks_triggered="0"
                            detection_rate_pct="N/A"

                            sm="$sim_dir/summary.csv"
                            if [ -f "$sm" ]; then
                                n_transactions=$(get_summary_value "$sm" "total_payments")
                                n_successful=$(get_summary_value "$sm" "successful_payments")
                                success_rate_pct=$(get_summary_value "$sm" "payment_success_rate_percent")
                                detection_rate_pct=$(get_summary_value "$sm" "malicious_detection_rate_percent")

                                # Calculate n_failed
                                if [[ "$n_transactions" != "N/A" ]] && [[ "$n_successful" != "N/A" ]]; then
                                    n_failed=$((n_transactions - n_successful))
                                else
                                    n_failed="N/A"
                                fi
                            fi

                            # --- avg_delay は baseline_metrics.csv を優先して取得 ---
                            baseline_file="$sim_dir/baseline_metrics.csv"
                            if [ -f "$baseline_file" ]; then
                                header=$(head -n1 "$baseline_file")
                                data=$(tail -n1 "$baseline_file")
                                IFS=',' read -ra headers <<< "$header"
                                IFS=',' read -ra values <<< "$data"
                                for i in "${!headers[@]}"; do
                                    if [[ "${headers[$i]}" == "avg_delay" ]]; then
                                        avg_delay_ms="${values[$i]}"
                                    fi
                                    if [[ "${headers[$i]}" == "total_attacks_triggered" ]]; then
                                        attacks_triggered="${values[$i]}"
                                    fi
                                done
                            fi

                            # stage4 の比較CSVがある場合はフォールバック
                            stage_file="$sim_dir/stage4_comparison.csv"
                            if [[ "$avg_delay_ms" == "N/A" || -z "$avg_delay_ms" ]] && [ -f "$stage_file" ]; then
                                avg_delay_ms=$(grep "^avg_payment_delay_ms," "$stage_file" 2>/dev/null | cut -d',' -f2 | tr -d '[:space:]' || echo "N/A")
                            fi

                            # summary.csv の time/average を最後のフォールバックとして使用
                            summary_file="$sim_dir/summary.csv"
                            if [[ "$avg_delay_ms" == "N/A" || -z "$avg_delay_ms" ]] && [ -f "$summary_file" ]; then
                                avg_delay_ms=$(get_summary_value "$summary_file" "time/average")
                            fi

                            # CSV行を出力 (include p value)
                            printf '%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,%s,%s,%s\n' \
                                "$defense_strategy" \
                                "$monitor_method_short" \
                                "$p" \
                                "$avg_pmt" \
                                "$payment_msat" \
                                "$monitor_count" \
                                "$n_transactions" \
                                "$n_successful" \
                                "$n_failed" \
                                "$success_rate_pct" \
                                "$avg_delay_ms" \
                                "$attacks_triggered" \
                                "$detection_rate_pct"
                        done # defense
                    done # p
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
