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
        mapfile -t simulation_progress_files < <(find "$output_dir" -type f -name "progress.tmp" ! -path "*/environment/*")

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

        echo "$progress_line"
        sleep 1
    done
}

for i in $(seq -6.0 1.0 1.0); do
    avg_fee_lim=$(python3 -c "print('{:.5f}'.format(10**$i))")
    var_fee_lim=$(python3 -c "print('{:.5f}'.format(10**$i/10))")
    enqueue_simulation         "./run-simulation.sh $seed $output_dir/routing_method=cloth_original/max_fee_limit=$avg_fee_lim    payment_timeout=-1 n_payments=5000 mpp=0 routing_method=cloth_original group_cap_update=      average_max_fee_limit=$avg_fee_lim  variance_max_fee_limit=$var_fee_lim  average_payment_amount=1000  variance_payment_amount=100  group_size=   group_limit_rate=   "
    enqueue_simulation         "./run-simulation.sh $seed $output_dir/routing_method=channel_update/max_fee_limit=$avg_fee_lim    payment_timeout=-1 n_payments=5000 mpp=0 routing_method=channel_update group_cap_update=      average_max_fee_limit=$avg_fee_lim  variance_max_fee_limit=$var_fee_lim  average_payment_amount=1000  variance_payment_amount=100  group_size=   group_limit_rate=   "
    enqueue_simulation         "./run-simulation.sh $seed $output_dir/routing_method=ideal/max_fee_limit=$avg_fee_lim             payment_timeout=-1 n_payments=5000 mpp=0 routing_method=ideal          group_cap_update=      average_max_fee_limit=$avg_fee_lim  variance_max_fee_limit=$var_fee_lim  average_payment_amount=1000  variance_payment_amount=100  group_size=   group_limit_rate=   "
    enqueue_simulation         "./run-simulation.sh $seed $output_dir/routing_method=group_routing/max_fee_limit=$avg_fee_lim     payment_timeout=-1 n_payments=5000 mpp=0 routing_method=group_routing  group_cap_update=true  average_max_fee_limit=$avg_fee_lim  variance_max_fee_limit=$var_fee_lim  average_payment_amount=1000  variance_payment_amount=100  group_size=10 group_limit_rate=0.1"
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
end_time=$(date +%s)
echo "START : $(date -r "$start_time" "+%Y-%m-%d %H:%M:%S")"
echo "  END : $(date -r "$end_time" "+%Y-%m-%d %H:%M:%S")"
elapsed=$((end_time - start_time))
hours=$((elapsed / 3600))
minutes=$(( (elapsed % 3600) / 60 ))
seconds=$((elapsed % 60))
echo " TIME : $(printf "%02d:%02d:%02d" $hours $minutes $seconds)"
