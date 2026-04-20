#!/opt/homebrew/bin/bash

if [[ "$#" -lt 1 ]]; then
  echo "./run_all_simulations.sh <seed> <output_dir>"
  exit 0
fi

seed="$1"

output_dir="$2/$(date "+%Y%m%d%H%M%S")"
mkdir -p "$output_dir"

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

    wait -n || true
    ((running_processes--))
}

function display_progress() {
    if [ "$total_simulations" -eq 0 ]; then
        return 0
    fi

    done_simulations=0

    while [ "$done_simulations" -lt "$total_simulations" ]; do
        # collect all progress.tmp files (one per simulation)
        mapfile -t simulation_progress_files < <(find "$output_dir" -type f -name "progress.tmp" ! -path "*/environment/*" 2>/dev/null)

        done_simulations=0
        for file in "${simulation_progress_files[@]}"; do
            progress=$(cat "$file" 2>/dev/null || echo "0")
            if [ "$progress" = "1" ]; then
                done_simulations=$((done_simulations + 1))
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
            progress_line=$(printf "Progress: [%-50s] 0%%\t%d/%d\t Time remaining --:--" "" "$done_simulations" "$total_simulations")
        else
            elapsed_time=$(( $(date +%s) - start_time ))
            estimated_completion_time=$(python3 -c "f=float('$fraction'); elapsed=$elapsed_time; print(int(elapsed / f - elapsed))")
            remaining_minutes=$(( estimated_completion_time / 60 ))
            remaining_seconds=$(( estimated_completion_time % 60 ))
            percent=$(echo "scale=1; $fraction * 100" | bc)
            progress_line=$(printf "Progress: [%-50s] %s%%\t%d/%d\t Time remaining %02d:%02d" "$progress_bar" "$percent" "$done_simulations" "$total_simulations" "$remaining_minutes" "$remaining_seconds")
        fi

        printf "\r\033[2K%s" "$progress_line"
        sleep 1
    done
    printf "\n"
}

for i in $(seq -6.0 1.0 1.0); do
    avg_fee_lim=$(python3 -c "print('{:.5f}'.format(10**$i))")
    var_fee_lim=$(python3 -c "print('{:.5f}'.format(10**$i/10))")

    for routing_method in cloth_original channel_update ideal group_routing; do
        if [ "$routing_method" = "group_routing" ]; then
            method_params="group_cap_update=true group_size=10 group_limit_rate=0.1"
        else
            method_params="group_cap_update= group_size= group_limit_rate="
        fi

        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/max_fee_limit=$avg_fee_lim/a_no_attack           payment_timeout=200000 n_payments=5000 mpp=0 routing_method=$routing_method malicious_node_ratio=0.0 malicious_failure_probability=0.0 monitoring_strategy=disabled top_hub_count=$TOP_HUB_COUNT enable_reputation_system=false enable_monitor_movement=false movement_credit_limit=0 enable_pra=false enable_prt=false enable_rbr=false average_max_fee_limit=$avg_fee_lim variance_max_fee_limit=$var_fee_lim average_payment_amount=1000 variance_payment_amount=100 $method_params"
        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/max_fee_limit=$avg_fee_lim/b_detection_only      payment_timeout=200000 n_payments=5000 mpp=0 routing_method=$routing_method malicious_node_ratio=$MALICIOUS_RATIO malicious_failure_probability=$ATTACK_SUCCESS_RATE monitoring_strategy=method2 top_hub_count=$TOP_HUB_COUNT enable_reputation_system=true enable_monitor_movement=false movement_credit_limit=0 enable_pra=false enable_prt=false enable_rbr=false average_max_fee_limit=$avg_fee_lim variance_max_fee_limit=$var_fee_lim average_payment_amount=1000 variance_payment_amount=100 $method_params"
        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/max_fee_limit=$avg_fee_lim/c_full_defense        payment_timeout=200000 n_payments=5000 mpp=0 routing_method=$routing_method malicious_node_ratio=$MALICIOUS_RATIO malicious_failure_probability=$ATTACK_SUCCESS_RATE monitoring_strategy=method2 top_hub_count=$TOP_HUB_COUNT enable_reputation_system=true enable_monitor_movement=true movement_credit_limit=5 enable_pra=true enable_prt=true enable_rbr=true rbr_reputation_weight=10.0 average_max_fee_limit=$avg_fee_lim variance_max_fee_limit=$var_fee_lim average_payment_amount=1000 variance_payment_amount=100 $method_params"
        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/max_fee_limit=$avg_fee_lim/d_extreme_no_defense payment_timeout=200000 n_payments=$EXT_N_PAYMENTS mpp=0 routing_method=$routing_method malicious_node_ratio=$EXT_MALICIOUS_RATIO malicious_failure_probability=$EXT_ATTACK_SUCCESS_RATE monitoring_strategy=disabled top_hub_count=$TOP_HUB_COUNT enable_reputation_system=false enable_monitor_movement=false movement_credit_limit=0 enable_pra=false enable_prt=false enable_rbr=false average_max_fee_limit=$avg_fee_lim variance_max_fee_limit=$var_fee_lim average_payment_amount=1000 variance_payment_amount=100 $method_params"
        enqueue_simulation "./run-simulation.sh $seed $output_dir/routing_method=$routing_method/max_fee_limit=$avg_fee_lim/e_extreme_full_defense payment_timeout=200000 n_payments=$EXT_N_PAYMENTS mpp=0 routing_method=$routing_method malicious_node_ratio=$EXT_MALICIOUS_RATIO malicious_failure_probability=$EXT_ATTACK_SUCCESS_RATE monitoring_strategy=method2 top_hub_count=$TOP_HUB_COUNT enable_reputation_system=true enable_monitor_movement=true movement_credit_limit=5 enable_pra=true enable_prt=true enable_rbr=true rbr_reputation_weight=10.0 average_max_fee_limit=$avg_fee_lim variance_max_fee_limit=$var_fee_lim average_payment_amount=1000 variance_payment_amount=100 $method_params"
    done
done

# Process the queue
display_progress &
while [ "${#queue[@]}" -gt 0 ] || [ "$running_processes" -gt 0 ]; do
    process_queue
    sleep 1
done
wait
echo -e "\nAll simulations have completed. \nOutputs saved at $output_dir"
python3 scripts/analyze_output.py "$output_dir"
python3 scripts/summarize_attack4.py "$output_dir"
end_time=$(date +%s)
echo "START : $(date -r "$start_time" "+%Y-%m-%d %H:%M:%S")"
echo "  END : $(date -r "$end_time" "+%Y-%m-%d %H:%M:%S")"
elapsed=$((end_time - start_time))
hours=$((elapsed / 3600))
minutes=$(( (elapsed % 3600) / 60 ))
seconds=$((elapsed % 60))
echo " TIME : $(printf "%02d:%02d:%02d" $hours $minutes $seconds)"
