#!/opt/homebrew/bin/bash

if [[ "$#" -lt 2 ]]; then
  echo "usage: $0 <seed> <output_dir> [remote_output_dir_or_smb_uri]"
  exit 0
fi

seed="$1"

output_dir="$2/$(date "+%Y%m%d%H%M%S")"
mkdir -p "$output_dir"
remote_arg="${3:-${REMOTE_OUTPUT_DIR:-}}"
remote_output_dir=""
if [[ -n "$remote_arg" ]]; then
    if [[ "$remote_arg" == smb://172.20.86.110/public1/* ]]; then
        remote_arg="/Volumes/public1/${remote_arg#smb://172.20.86.110/public1/}"
    elif [[ "$remote_arg" == smb://* ]]; then
        echo "WARN: unsupported SMB URI format: $remote_arg"
        echo "      mount SMB first and pass local mount path (e.g. /Volumes/public1/...)."
        remote_arg=""
    fi
    if [[ -n "$remote_arg" ]]; then
        remote_output_dir="$remote_arg/$(basename "$output_dir")"
        if ! mkdir -p "$remote_output_dir"; then
            echo "WARN: cannot create remote output dir <$remote_output_dir>; offload disabled."
            remote_output_dir=""
        fi
    fi
fi

max_processes=32

queue=()
running_processes=0
total_simulations=0
start_time=$(date +%s)

# Attack / defense parameters
MALICIOUS_RATIO=0.15
ATTACK_SUCCESS_RATE=0.80
TOP_HUB_COUNT=10

# Extreme attack condition parameters
EXT_N_PAYMENTS=2000
EXT_MALICIOUS_RATIO=0.25
EXT_ATTACK_SUCCESS_RATE=0.95

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

function move_completed_to_remote() {
    if [[ -z "$remote_output_dir" ]]; then
        return 0
    fi
    mapfile -t simulation_progress_files < <(find "$output_dir" -type f -name "progress.tmp" ! -path "*/environment/*" 2>/dev/null)
    for file in "${simulation_progress_files[@]}"; do
        sim_dir="$(dirname "$file")"
        if [[ -f "$sim_dir/.moved_to_remote" ]]; then
            continue
        fi
        progress=$(cat "$file" 2>/dev/null || echo "0")
        if [[ "$progress" != "1" && "$progress" != "failed" ]]; then
            continue
        fi
        rel_path="${sim_dir#$output_dir/}"
        if [[ "$rel_path" == "$sim_dir" ]]; then
            continue
        fi
        dest_dir="$remote_output_dir/$rel_path"
        mkdir -p "$dest_dir" || continue
        if rsync -a "$sim_dir/" "$dest_dir/" > /dev/null 2>&1; then
            rm -rf "$sim_dir"
            mkdir -p "$sim_dir"
            echo "$progress" > "$sim_dir/progress.tmp"
            echo "$dest_dir" > "$sim_dir/.moved_to_remote"
        fi
    done
}

function display_progress() {
    if [ "$total_simulations" -eq 0 ]; then
        return 0
    fi

    done_simulations=0
    failed_simulations=0

    while [ "$done_simulations" -lt "$total_simulations" ]; do
        move_completed_to_remote
        # collect all progress.tmp files (one per simulation)
        mapfile -t simulation_progress_files < <(find "$output_dir" -type f -name "progress.tmp" ! -path "*/environment/*" 2>/dev/null)

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

        # build progress bar from 0..50 characters
        filled=$(printf "%.0f" "$(echo "$fraction * 50" | bc)")
        progress_bar=$(printf "%0.s#" $(seq 1 "$filled"))

        if [ "$(python3 -c "print(float('$fraction')==0.0)")" = "True" ]; then
            progress_line=$(printf "Progress: [%-50s] 0%%\t%d/%d\t Failed %d\t Time remaining --:--:--" "" "$done_simulations" "$total_simulations" "$failed_simulations")
        else
            elapsed_time=$(( $(date +%s) - start_time ))
            remaining_time_sec=$(python3 -c "f=float('$fraction'); elapsed=$elapsed_time; est=int(elapsed / f - elapsed); print(max(0, est))")
            remaining_hours=$(( remaining_time_sec / 3600 ))
            remaining_minutes=$(( (remaining_time_sec % 3600) / 60 ))
            remaining_seconds=$(( remaining_time_sec % 60 ))
            percent=$(echo "scale=1; $fraction * 100" | bc)
            progress_line=$(printf "Progress: [%-50s] %s%%\t%d/%d\t Failed %d\t Time remaining %02d:%02d:%02d" "$progress_bar" "$percent" "$done_simulations" "$total_simulations" "$failed_simulations" "$remaining_hours" "$remaining_minutes" "$remaining_seconds")
        fi

        printf "\r\033[2K%s" "$progress_line"
        sleep 1
    done
    printf "\n"
}

for i in $(seq 1.0 0.2 5.0); do
    avg_pmt_amt=$(python3 -c "print('{:.0f}'.format(10**$i))")
    var_pmt_amt=$(("$avg_pmt_amt"/10))

    for routing_method in cloth_original ideal group_routing; do
        if [ "$routing_method" = "group_routing" ]; then
            method_params="group_cap_update=true group_size=10 group_limit_rate=0.1"
        else
            method_params="group_cap_update= group_size= group_limit_rate="
        fi

        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/average_payment_amount=$avg_pmt_amt/a_no_attack           payment_timeout=200000 n_payments=5000 mpp=0 routing_method=$routing_method malicious_node_ratio=0.0 malicious_failure_probability=0.0 monitoring_strategy=disabled top_hub_count=$TOP_HUB_COUNT enable_reputation_system=false enable_monitor_movement=false movement_credit_limit=0 enable_pra=false enable_prt=false enable_rbr=false average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $method_params"
        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/average_payment_amount=$avg_pmt_amt/b_detection_only      payment_timeout=200000 n_payments=5000 mpp=0 routing_method=$routing_method malicious_node_ratio=$MALICIOUS_RATIO malicious_failure_probability=$ATTACK_SUCCESS_RATE monitoring_strategy=method2 top_hub_count=$TOP_HUB_COUNT enable_reputation_system=true enable_monitor_movement=false movement_credit_limit=0 enable_pra=false enable_prt=false enable_rbr=false average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $method_params"
        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/average_payment_amount=$avg_pmt_amt/c_full_defense        payment_timeout=200000 n_payments=5000 mpp=0 routing_method=$routing_method malicious_node_ratio=$MALICIOUS_RATIO malicious_failure_probability=$ATTACK_SUCCESS_RATE monitoring_strategy=method2 top_hub_count=$TOP_HUB_COUNT enable_reputation_system=true enable_monitor_movement=true movement_credit_limit=5 enable_pra=true enable_prt=true enable_rbr=true rbr_reputation_weight=10.0 average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $method_params"
        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/average_payment_amount=$avg_pmt_amt/d_extreme_no_defense payment_timeout=200000 n_payments=$EXT_N_PAYMENTS mpp=0 routing_method=$routing_method malicious_node_ratio=$EXT_MALICIOUS_RATIO malicious_failure_probability=$EXT_ATTACK_SUCCESS_RATE monitoring_strategy=disabled top_hub_count=$TOP_HUB_COUNT enable_reputation_system=false enable_monitor_movement=false movement_credit_limit=0 enable_pra=false enable_prt=false enable_rbr=false average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $method_params"
        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/average_payment_amount=$avg_pmt_amt/e_extreme_full_defense payment_timeout=200000 n_payments=$EXT_N_PAYMENTS mpp=0 routing_method=$routing_method malicious_node_ratio=$EXT_MALICIOUS_RATIO malicious_failure_probability=$EXT_ATTACK_SUCCESS_RATE monitoring_strategy=method2 top_hub_count=$TOP_HUB_COUNT enable_reputation_system=true enable_monitor_movement=true movement_credit_limit=5 enable_pra=true enable_prt=true enable_rbr=true rbr_reputation_weight=10.0 average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $method_params"
    done

    for cul_threshold_dist_alpha in $(seq 1 2 20); do
        for cul_threshold_dist_beta in $(seq 1 2 20); do
            cul_base="$output_dir/routing_method=group_routing_cul/cul_threshold_dist_alpha=$cul_threshold_dist_alpha/cul_threshold_dist_beta=$cul_threshold_dist_beta/average_payment_amount=$avg_pmt_amt"
            cul_params="group_cap_update=true group_size=10 group_limit_rate= cul_threshold_dist_alpha=$cul_threshold_dist_alpha cul_threshold_dist_beta=$cul_threshold_dist_beta"

            enqueue_simulation "./run-simulation.sh $seed $cul_base/a_no_attack           payment_timeout=200000 n_payments=5000 mpp=0 routing_method=group_routing_cul malicious_node_ratio=0.0 malicious_failure_probability=0.0 monitoring_strategy=disabled top_hub_count=$TOP_HUB_COUNT enable_reputation_system=false enable_monitor_movement=false movement_credit_limit=0 enable_pra=false enable_prt=false enable_rbr=false average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $cul_params"
            enqueue_simulation "./run-simulation.sh $seed $cul_base/b_detection_only      payment_timeout=200000 n_payments=5000 mpp=0 routing_method=group_routing_cul malicious_node_ratio=$MALICIOUS_RATIO malicious_failure_probability=$ATTACK_SUCCESS_RATE monitoring_strategy=method2 top_hub_count=$TOP_HUB_COUNT enable_reputation_system=true enable_monitor_movement=false movement_credit_limit=0 enable_pra=false enable_prt=false enable_rbr=false average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $cul_params"
            enqueue_simulation "./run-simulation.sh $seed $cul_base/c_full_defense        payment_timeout=200000 n_payments=5000 mpp=0 routing_method=group_routing_cul malicious_node_ratio=$MALICIOUS_RATIO malicious_failure_probability=$ATTACK_SUCCESS_RATE monitoring_strategy=method2 top_hub_count=$TOP_HUB_COUNT enable_reputation_system=true enable_monitor_movement=true movement_credit_limit=5 enable_pra=true enable_prt=true enable_rbr=true rbr_reputation_weight=10.0 average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $cul_params"
            enqueue_simulation "./run-simulation.sh $seed $cul_base/d_extreme_no_defense payment_timeout=200000 n_payments=$EXT_N_PAYMENTS mpp=0 routing_method=group_routing_cul malicious_node_ratio=$EXT_MALICIOUS_RATIO malicious_failure_probability=$EXT_ATTACK_SUCCESS_RATE monitoring_strategy=disabled top_hub_count=$TOP_HUB_COUNT enable_reputation_system=false enable_monitor_movement=false movement_credit_limit=0 enable_pra=false enable_prt=false enable_rbr=false average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $cul_params"
            enqueue_simulation "./run-simulation.sh $seed $cul_base/e_extreme_full_defense payment_timeout=200000 n_payments=$EXT_N_PAYMENTS mpp=0 routing_method=group_routing_cul malicious_node_ratio=$EXT_MALICIOUS_RATIO malicious_failure_probability=$EXT_ATTACK_SUCCESS_RATE monitoring_strategy=method2 top_hub_count=$TOP_HUB_COUNT enable_reputation_system=true enable_monitor_movement=true movement_credit_limit=5 enable_pra=true enable_prt=true enable_rbr=true rbr_reputation_weight=10.0 average_payment_amount=$avg_pmt_amt variance_payment_amount=$var_pmt_amt $cul_params"
        done
    done
done

# Process the queue
display_progress &
while [ "${#queue[@]}" -gt 0 ] || [ "$running_processes" -gt 0 ]; do
    process_queue
    sleep 1
done
wait
move_completed_to_remote
echo -e "\nAll simulations have completed. \nOutputs saved at $output_dir"
if [[ -n "$remote_output_dir" ]]; then
    echo "Completed runs were offloaded to $remote_output_dir"
fi
analysis_input="$output_dir"
if [[ -n "$remote_output_dir" ]]; then
    analysis_input="$remote_output_dir"
fi
python3 scripts/analyze_output.py "$analysis_input"
python3 scripts/summarize_attack4.py "$analysis_input"
end_time=$(date +%s)
echo "START : $(date -r "$start_time" "+%Y-%m-%d %H:%M:%S")"
echo "  END : $(date -r "$end_time" "+%Y-%m-%d %H:%M:%S")"
elapsed=$((end_time - start_time))
hours=$((elapsed / 3600))
minutes=$(( (elapsed % 3600) / 60 ))
seconds=$((elapsed % 60))
echo " TIME : $(printf "%02d:%02d:%02d" $hours $minutes $seconds)"
