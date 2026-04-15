#!/opt/homebrew/bin/bash

if [[ "$#" -lt 2 ]]; then
  echo "usage: $0 <seed_start> <output_dir> [n_seeds]"
  echo "example: $0 42 /tmp/cloth-batch 5"
  exit 1
fi

seed_start="$1"
output_root="$2/$(date "+%Y%m%d%H%M%S")"
n_seeds="${3:-1}"

mkdir -p "$output_root"

max_processes=12
queue=()
running_processes=0
total_simulations=0
start_time=$(date +%s)

N_PAYMENTS=5000
MALICIOUS_RATIO=0.15
ATTACK_SUCCESS_RATE=0.80

# Extreme attack condition parameters (25% malicious, 95% attack success)
EXT_N_PAYMENTS=2000
EXT_MALICIOUS_RATIO=0.25
EXT_ATTACK_SUCCESS_RATE=0.95

TOP_HUB_COUNT=10
TOP_HUB_IDS=""

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
        mapfile -t simulation_progress_files < <(find "$output_root" -type f -name "progress.tmp" ! -path "*/environment/*")

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
            progress_line=$(printf "Progress: [%-50s] 0%%\t%d/%d\tETA --:--" "" "$done_simulations" "$total_simulations")
        else
            elapsed_time=$(( $(date +%s) - start_time ))
            estimated_completion_time=$(python3 -c "f=float('$fraction'); elapsed=$elapsed_time; print(int(elapsed / f - elapsed))")
            remaining_minutes=$(( estimated_completion_time / 60 ))
            remaining_seconds=$(( estimated_completion_time % 60 ))
            percent=$(echo "scale=1; $fraction * 100" | bc)
            progress_line=$(printf "Progress: [%-50s] %s%%\t%d/%d\tETA %02d:%02d" "$progress_bar" "$percent" "$done_simulations" "$total_simulations" "$remaining_minutes" "$remaining_seconds")
        fi

        echo "$progress_line"
        sleep 1
    done
}

if [ -f "Python/network_analysis/network_analysis.py" ]; then
  (
    cd Python
    python3 network_analysis/network_analysis.py > /dev/null 2>&1 || true
  )

  if [ -f "Python/network_analysis/output/pagerank_weightscaled.csv" ]; then
    TOP_HUB_IDS=$(python3 - << 'PY'
import csv
path = "Python/network_analysis/output/pagerank_weightscaled.csv"
hub_ids = []
with open(path, newline="") as f:
    for row in csv.DictReader(f):
        hub_ids.append(row["Node_ID"])
        if len(hub_ids) >= 10:
            break
print(",".join(hub_ids))
PY
)
    if [ -n "$TOP_HUB_IDS" ]; then
      TOP_HUB_COUNT=$(echo "$TOP_HUB_IDS" | awk -F',' '{print NF}')
      if [ "$TOP_HUB_COUNT" -le 0 ]; then
        TOP_HUB_COUNT=10
      fi
    fi
  fi
fi

for s in $(seq "$seed_start" $((seed_start + n_seeds - 1))); do
    seed_dir="$output_root/seed=$s"
    mkdir -p "$seed_dir"

    enqueue_simulation "./run-simulation.sh $s $seed_dir/a_no_attack/ \
        n_payments=$N_PAYMENTS \
        malicious_node_ratio=0.0 \
        malicious_failure_probability=0.0 \
        monitoring_strategy=disabled \
        enable_reputation_system=false \
        enable_monitor_movement=false \
        movement_credit_limit=0 \
        enable_pra=false \
        enable_prt=false \
        enable_rbr=false \
        routing_method=cloth_original"

    enqueue_simulation "./run-simulation.sh $s $seed_dir/b_detection_only/ \
        n_payments=$N_PAYMENTS \
        malicious_node_ratio=$MALICIOUS_RATIO \
        malicious_failure_probability=$ATTACK_SUCCESS_RATE \
        monitoring_strategy=method2 \
        top_hub_count=$TOP_HUB_COUNT \
        enable_reputation_system=true \
        enable_monitor_movement=false \
        movement_credit_limit=0 \
        enable_pra=false \
        enable_prt=false \
        enable_rbr=false \
        routing_method=cloth_original"

    enqueue_simulation "./run-simulation.sh $s $seed_dir/c_full_defense/ \
        n_payments=$N_PAYMENTS \
        malicious_node_ratio=$MALICIOUS_RATIO \
        malicious_failure_probability=$ATTACK_SUCCESS_RATE \
        monitoring_strategy=method2 \
        top_hub_count=$TOP_HUB_COUNT \
        enable_reputation_system=true \
        enable_monitor_movement=true \
        movement_credit_limit=5 \
        enable_pra=true \
        enable_prt=true \
        enable_rbr=true \
        rbr_reputation_weight=10.0 \
        routing_method=cloth_original"

    # Extreme attack scenarios (25% malicious, 95% attack success)
    enqueue_simulation "./run-simulation.sh $s $seed_dir/d_extreme_no_defense/ \
        n_payments=$EXT_N_PAYMENTS \
        malicious_node_ratio=$EXT_MALICIOUS_RATIO \
        malicious_failure_probability=$EXT_ATTACK_SUCCESS_RATE \
        monitoring_strategy=disabled \
        enable_reputation_system=false \
        enable_monitor_movement=false \
        movement_credit_limit=0 \
        enable_pra=false \
        enable_prt=false \
        enable_rbr=false \
        routing_method=cloth_original"

    enqueue_simulation "./run-simulation.sh $s $seed_dir/e_extreme_detection_only/ \
        n_payments=$EXT_N_PAYMENTS \
        malicious_node_ratio=$EXT_MALICIOUS_RATIO \
        malicious_failure_probability=$EXT_ATTACK_SUCCESS_RATE \
        monitoring_strategy=method2 \
        top_hub_count=$TOP_HUB_COUNT \
        enable_reputation_system=true \
        enable_monitor_movement=false \
        movement_credit_limit=0 \
        enable_pra=false \
        enable_prt=false \
        enable_rbr=false \
        routing_method=cloth_original"

    enqueue_simulation "./run-simulation.sh $s $seed_dir/f_extreme_full_defense/ \
        n_payments=$EXT_N_PAYMENTS \
        malicious_node_ratio=$EXT_MALICIOUS_RATIO \
        malicious_failure_probability=$EXT_ATTACK_SUCCESS_RATE \
        monitoring_strategy=method2 \
        top_hub_count=$TOP_HUB_COUNT \
        enable_reputation_system=true \
        enable_monitor_movement=true \
        movement_credit_limit=5 \
        enable_pra=true \
        enable_prt=true \
        enable_rbr=true \
        rbr_reputation_weight=10.0 \
        routing_method=cloth_original"
done

display_progress &
while [ "${#queue[@]}" -gt 0 ] || [ "$running_processes" -gt 0 ]; do
    process_queue
    sleep 1
done
wait

summary_csv="$output_root/summary_detection_defense.csv"
TOP_HUB_COUNT="$TOP_HUB_COUNT" TOP_HUB_IDS="$TOP_HUB_IDS" python3 - "$output_root" "$summary_csv" << 'PY'
import csv
import glob
import os
import sys
import json

root = sys.argv[1]
out = sys.argv[2]
top_hub_count = os.environ.get("TOP_HUB_COUNT", "")
top_hub_ids = os.environ.get("TOP_HUB_IDS", "")

rows = []
for baseline in glob.glob(os.path.join(root, "seed=*", "*", "baseline_metrics.csv")):
    scenario_dir = os.path.dirname(baseline)
    scenario = os.path.basename(scenario_dir)
    seed = os.path.basename(os.path.dirname(scenario_dir)).split("=", 1)[1]
    with open(baseline, newline="") as f:
        b = next(csv.DictReader(f))

    # Monitor metrics
    monitor_metrics = os.path.join(scenario_dir, "monitor_metrics.csv")
    active_monitors = 0
    cumulative_monitors = 0
    if os.path.exists(monitor_metrics):
        with open(monitor_metrics, newline="") as f:
            m = next(csv.DictReader(f))
            active_monitors = int(m.get("num_monitors", 0))
            cumulative_monitors = int(m.get("cumulative_monitor_assignments", active_monitors))

    # Per-payment delay breakdown (success without attack vs success after attack)
    payments_path = os.path.join(scenario_dir, "payments_output.csv")
    clean_delay_sum = 0.0
    clean_count = 0
    attacked_delay_sum = 0.0
    attacked_count = 0
    if os.path.exists(payments_path):
        with open(payments_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    start = float(row.get("start_time", 0))
                    end = float(row.get("end_time", 0))
                except ValueError:
                    continue
                delay = end - start
                is_success = row.get("is_success", "0") == "1"
                if not is_success:
                    continue
                attacked = False
                hist_raw = row.get("attempts_history", "")
                if hist_raw:
                    try:
                        hist = json.loads(hist_raw)
                        for h in hist:
                            if int(h.get("error_type", 0)) != 0:
                                attacked = True
                                break
                    except Exception:
                        attacked = False
                if attacked:
                    attacked_delay_sum += delay
                    attacked_count += 1
                else:
                    clean_delay_sum += delay
                    clean_count += 1

    clean_avg = (clean_delay_sum / clean_count) if clean_count > 0 else ""
    attacked_avg = (attacked_delay_sum / attacked_count) if attacked_count > 0 else ""

    rows.append({
        "seed": seed,
        "scenario": scenario,
        "success_rate": b["success_rate"],
        "avg_delay": b["avg_delay"],
        "n_failed": b["n_failed"],
        "total_attacks_triggered": b["total_attacks_triggered"],
        "active_monitors": active_monitors,
        "cumulative_monitors": cumulative_monitors,
        "top_hub_count_used": top_hub_count,
        "top_hub_ids_used": top_hub_ids,
        "clean_success_delay_avg": clean_avg,
        "attacked_success_delay_avg": attacked_avg,
        "n_clean_success": clean_count,
        "n_attacked_success": attacked_count,
    })

rows.sort(key=lambda r: (int(r["seed"]), r["scenario"]))
with open(out, "w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "seed", "scenario", "success_rate", "avg_delay", "n_failed",
            "total_attacks_triggered", "active_monitors", "cumulative_monitors",
            "top_hub_count_used", "top_hub_ids_used",
            "clean_success_delay_avg", "attacked_success_delay_avg",
            "n_clean_success", "n_attacked_success",
        ],
    )
    writer.writeheader()
    writer.writerows(rows)
print(out)
PY

if [ -f "scripts/analyze_output.py" ]; then
  python3 scripts/analyze_output.py "$output_root" > /dev/null 2>&1 || true
fi

python_analysis_root="$output_root/python_network_analysis"
mkdir -p "$python_analysis_root"

if [ -d "Python/network_analysis" ]; then
  if [ -d "Python/network_analysis/output" ]; then
    cp -R "Python/network_analysis/output/." "$python_analysis_root/" 2>/dev/null || true
  fi
fi

{
  echo "top_hub_count=$TOP_HUB_COUNT"
  echo "top_hub_ids=$TOP_HUB_IDS"
} > "$output_root/python_network_profile.txt"

echo -e "\nAll simulations completed."
echo "Outputs: $output_root"
echo "Summary: $summary_csv"
echo "Python analysis outputs: $python_analysis_root"
echo "Python profile: $output_root/python_network_profile.txt"

end_time=$(date +%s)
echo "START : $(date -r "$start_time" "+%Y-%m-%d %H:%M:%S")"
echo "  END : $(date -r "$end_time" "+%Y-%m-%d %H:%M:%S")"
elapsed=$((end_time - start_time))
hours=$((elapsed / 3600))
minutes=$(( (elapsed % 3600) / 60 ))
seconds=$((elapsed % 60))
echo " TIME : $(printf "%02d:%02d:%02d" $hours $minutes $seconds)"
