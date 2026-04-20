#!/bin/bash
#
# test_with_without_detection.sh
#
# 攻撃シナリオで、検知・回避の有無による成功率の比較
# 
# Test A: No Detection, No Avoidance (reputation disabled)
# Test B: Detection Only (reputation enabled, but routing ignores it)
# Test C: Full Defense (reputation enabled, RBR routing enabled)
#

set -e

OUTPUT_BASE="/tmp/cloth-detection-test-$$"
mkdir -p "$OUTPUT_BASE"

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║   攻撃検知・回避効果の比較テスト                                            ║"
echo "║   Comparison: No Detection vs Detection Only vs Full Defense               ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Output Base: $OUTPUT_BASE"
echo ""

# Test Parameters
SEED=42
N_PAYMENTS=5000
MALICIOUS_RATIO_A=0.0
MALICIOUS_RATIO_BC=0.15
ATTACK_SUCCESS_RATE_A=0.0
ATTACK_SUCCESS_RATE_BC=0.80

echo "Parameters:"
echo "  - n_payments: $N_PAYMENTS"
echo "  - A malicious_node_ratio: $MALICIOUS_RATIO_A"
echo "  - B/C malicious_node_ratio: $MALICIOUS_RATIO_BC"
echo "  - A attack_success_rate: $ATTACK_SUCCESS_RATE_A"
echo "  - B/C attack_success_rate: $ATTACK_SUCCESS_RATE_BC"
echo ""

# ============================================================================
# Test A: No Detection, No Avoidance
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test A: No Attack (Clean Baseline)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TEST_A_DIR="$OUTPUT_BASE/test_a_no_defense"
mkdir -p "$TEST_A_DIR"

./run-simulation.sh $SEED "$TEST_A_DIR/" \
    n_payments=$N_PAYMENTS \
    malicious_node_ratio=$MALICIOUS_RATIO_A \
    malicious_failure_probability=$ATTACK_SUCCESS_RATE_A \
    monitoring_strategy=disabled \
    enable_reputation_system=false \
    enable_monitor_movement=false \
    movement_credit_limit=0 \
    enable_pra=false \
    enable_prt=false \
    enable_rbr=false \
    routing_method=cloth_original \
    2>&1 | tail -20

echo ""
echo "Test A completed. Analyzing results..."

if [ -f "$TEST_A_DIR/payments_output.csv" ]; then
  TOTAL_A=$(tail -n +2 "$TEST_A_DIR/payments_output.csv" | wc -l)
  SUCCESS_A=$(tail -n +2 "$TEST_A_DIR/payments_output.csv" | awk -F',' '$9=="1" {count++} END {print count+0}')
  FAIL_A=$(tail -n +2 "$TEST_A_DIR/payments_output.csv" | awk -F',' '$9=="0" {count++} END {print count+0}')
  
  SUCCESS_RATE_A=$(echo "scale=2; $SUCCESS_A * 100 / $TOTAL_A" | bc 2>/dev/null || echo "N/A")
  
  echo "Test A Results:"
  echo "  Total:   $TOTAL_A"
  echo "  Success: $SUCCESS_A"
  echo "  Fail:    $FAIL_A"
  echo "  Success Rate: $SUCCESS_RATE_A%"
else
  echo "ERROR: Test A output file not found"
fi

echo ""

# ============================================================================
# Test B: Detection Only (reputation tracking, but no RBR routing)
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test B: Attack with Detection Only (no RBR routing)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TEST_B_DIR="$OUTPUT_BASE/test_b_detection_only"
mkdir -p "$TEST_B_DIR"

./run-simulation.sh $SEED "$TEST_B_DIR/" \
    n_payments=$N_PAYMENTS \
    malicious_node_ratio=$MALICIOUS_RATIO_BC \
    malicious_failure_probability=$ATTACK_SUCCESS_RATE_BC \
    monitoring_strategy=method2 \
    enable_reputation_system=true \
    enable_monitor_movement=false \
    movement_credit_limit=0 \
    enable_pra=false \
    enable_prt=false \
    enable_rbr=false \
    routing_method=cloth_original \
    2>&1 | tail -20

echo ""
echo "Test B completed. Analyzing results..."

if [ -f "$TEST_B_DIR/payments_output.csv" ]; then
  TOTAL_B=$(tail -n +2 "$TEST_B_DIR/payments_output.csv" | wc -l)
  SUCCESS_B=$(tail -n +2 "$TEST_B_DIR/payments_output.csv" | awk -F',' '$9=="1" {count++} END {print count+0}')
  FAIL_B=$(tail -n +2 "$TEST_B_DIR/payments_output.csv" | awk -F',' '$9=="0" {count++} END {print count+0}')
  
  SUCCESS_RATE_B=$(echo "scale=2; $SUCCESS_B * 100 / $TOTAL_B" | bc 2>/dev/null || echo "N/A")
  
  echo "Test B Results:"
  echo "  Total:   $TOTAL_B"
  echo "  Success: $SUCCESS_B"
  echo "  Fail:    $FAIL_B"
  echo "  Success Rate: $SUCCESS_RATE_B%"
else
  echo "ERROR: Test B output file not found"
fi

echo ""

# ============================================================================
# Test C: Full Defense (reputation tracking + RBR routing)
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test C: Attack with Full Defense (detection + RBR routing)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TEST_C_DIR="$OUTPUT_BASE/test_c_full_defense"
mkdir -p "$TEST_C_DIR"

./run-simulation.sh $SEED "$TEST_C_DIR/" \
    n_payments=$N_PAYMENTS \
    malicious_node_ratio=$MALICIOUS_RATIO_BC \
    malicious_failure_probability=$ATTACK_SUCCESS_RATE_BC \
    monitoring_strategy=method2 \
    enable_reputation_system=true \
    enable_monitor_movement=true \
    movement_credit_limit=5 \
    enable_pra=true \
    enable_prt=true \
    enable_rbr=true \
    routing_method=cloth_original \
    2>&1 | tail -20

echo ""
echo "Test C completed. Analyzing results..."

if [ -f "$TEST_C_DIR/payments_output.csv" ]; then
  TOTAL_C=$(tail -n +2 "$TEST_C_DIR/payments_output.csv" | wc -l)
  SUCCESS_C=$(tail -n +2 "$TEST_C_DIR/payments_output.csv" | awk -F',' '$9=="1" {count++} END {print count+0}')
  FAIL_C=$(tail -n +2 "$TEST_C_DIR/payments_output.csv" | awk -F',' '$9=="0" {count++} END {print count+0}')
  
  SUCCESS_RATE_C=$(echo "scale=2; $SUCCESS_C * 100 / $TOTAL_C" | bc 2>/dev/null || echo "N/A")
  
  echo "Test C Results:"
  echo "  Total:   $TOTAL_C"
  echo "  Success: $SUCCESS_C"
  echo "  Fail:    $FAIL_C"
  echo "  Success Rate: $SUCCESS_RATE_C%"
else
  echo "ERROR: Test C output file not found"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "COMPARISON SUMMARY"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

if [ -n "$SUCCESS_RATE_A" ] && [ -n "$SUCCESS_RATE_B" ] && [ -n "$SUCCESS_RATE_C" ]; then
  echo "Test A (No Detection & No Avoidance):     $SUCCESS_RATE_A%  ($SUCCESS_A/$TOTAL_A)"
  echo "Test B (Detection Only):                   $SUCCESS_RATE_B%  ($SUCCESS_B/$TOTAL_B)"
  echo "Test C (Full Defense + RBR):               $SUCCESS_RATE_C%  ($SUCCESS_C/$TOTAL_C)"
  echo ""
  
  IMPROVEMENT_B=$(echo "scale=2; $SUCCESS_RATE_B - $SUCCESS_RATE_A" | bc 2>/dev/null || echo "N/A")
  IMPROVEMENT_C=$(echo "scale=2; $SUCCESS_RATE_C - $SUCCESS_RATE_A" | bc 2>/dev/null || echo "N/A")
  
  echo "Improvements vs No Defense:"
  echo "  Detection Only:     +$IMPROVEMENT_B%"
  echo "  Full Defense (RBR):  +$IMPROVEMENT_C%"
fi

echo ""
echo "Output Directory: $OUTPUT_BASE"
echo ""
echo "Detailed Results:"
echo "  Test A: $TEST_A_DIR/payments_output.csv"
echo "  Test B: $TEST_B_DIR/payments_output.csv"
echo "  Test C: $TEST_C_DIR/payments_output.csv"
echo ""

python3 - "$OUTPUT_BASE" << 'PYTHON'
import csv
import os
import sys

if len(sys.argv) < 2:
    print("ERROR: output_base argument is missing; cannot compute evaluation metrics.")
    raise SystemExit(1)
output_base = sys.argv[1]

scenarios = {
    "A_no_defense": os.path.join(output_base, "test_a_no_defense"),
    "B_detection_only": os.path.join(output_base, "test_b_detection_only"),
    "C_full_defense": os.path.join(output_base, "test_c_full_defense"),
}

def read_baseline(path):
    f = os.path.join(path, "baseline_metrics.csv")
    if not os.path.exists(f):
        return None
    with open(f, newline="") as fp:
        return next(csv.DictReader(fp))

def read_reputation(path):
    f = os.path.join(path, "reputation_dynamics.csv")
    if not os.path.exists(f):
        return None
    with open(f, newline="") as fp:
        return list(csv.DictReader(fp))

def read_payments(path):
    f = os.path.join(path, "payments_output.csv")
    if not os.path.exists(f):
        return None
    with open(f, newline="") as fp:
        return list(csv.DictReader(fp))

def read_monitor_metrics(path):
    f = os.path.join(path, "monitor_metrics.csv")
    if not os.path.exists(f):
        return None
    with open(f, newline="") as fp:
        return next(csv.DictReader(fp))

def read_config(path):
    cfg = {}
    f = os.path.join(path, "cloth_input.txt")
    if not os.path.exists(f):
        return cfg
    with open(f) as fp:
        for line in fp:
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k] = v
    return cfg

metrics = {}
for name, path in scenarios.items():
    baseline = read_baseline(path)
    reputation = read_reputation(path)
    payments = read_payments(path)
    monitor = read_monitor_metrics(path)
    cfg = read_config(path)

    if baseline is None or payments is None:
        metrics[name] = None
        continue

    n_failed = int(baseline["n_failed"])
    success_rate = float(baseline["success_rate"])
    avg_delay = float(baseline["avg_delay"])
    total_attacks = int(baseline["total_attacks_triggered"])

    detection_enabled = (
        cfg.get("enable_reputation_system", "false") == "true"
        and cfg.get("monitoring_strategy", "disabled") != "disabled"
    )

    malicious_total = None
    malicious_detected = None
    detection_coverage = None
    detection_latency_ms = None
    if detection_enabled and reputation:
        malicious_nodes = [r for r in reputation if int(r["is_malicious"]) == 1]
        attacking_nodes = [r for r in malicious_nodes if int(r.get("first_attack_time", "0")) > 0]
        detected_after_attack = [
            r for r in attacking_nodes
            if int(r.get("first_detection_time", "0")) >= int(r.get("first_attack_time", "0"))
            and int(r.get("first_detection_time", "0")) > 0
        ]
        latencies = [int(r["first_detection_time"]) - int(r["first_attack_time"]) for r in detected_after_attack]

        malicious_total = len(attacking_nodes)
        malicious_detected = len(detected_after_attack)
        if malicious_total > 0:
            detection_coverage = malicious_detected / malicious_total
        if latencies:
            detection_latency_ms = sum(latencies) / len(latencies)

    avg_amount_msat = sum(int(p["amount"]) for p in payments) / len(payments) if payments else 0
    num_monitors = int(monitor["num_monitors"]) if monitor else 0
    cumulative_monitors = int(monitor.get("cumulative_monitor_assignments", monitor["num_monitors"])) if monitor else 0
    movement_credit_limit = int(cfg.get("movement_credit_limit", "0") or "0")
    movement_budget_credits = cumulative_monitors * movement_credit_limit

    metrics[name] = {
        "scenario": name,
        "success_rate": success_rate,
        "avg_delay_ms": avg_delay,
        "n_failed": n_failed,
        "total_attacks_triggered": total_attacks,
        "detection_latency_ms": detection_latency_ms,
        "malicious_total": malicious_total,
        "malicious_detected": malicious_detected,
        "detection_coverage": detection_coverage,
        "num_monitors": num_monitors,
        "cumulative_monitors": cumulative_monitors,
        "movement_credit_limit": movement_credit_limit,
        "movement_budget_credits": movement_budget_credits,
        "avg_amount_msat": avg_amount_msat,
    }

base = metrics.get("A_no_defense")
if base:
    for name in ("B_detection_only", "C_full_defense"):
        m = metrics.get(name)
        if not m:
            continue
        prevented_failures = base["n_failed"] - m["n_failed"]
        prevented_damage_msat = prevented_failures * base["avg_amount_msat"]
        m["prevented_failures_vs_a"] = prevented_failures
        m["prevented_damage_msat_vs_a"] = prevented_damage_msat
        if m["movement_budget_credits"] > 0:
            m["cost_efficiency_msat_per_credit"] = prevented_damage_msat / m["movement_budget_credits"]
        else:
            m["cost_efficiency_msat_per_credit"] = None

print("════════════════════════════════════════════════════════════════════════════")
print("EVALUATION METRICS (a/b/c)")
print("════════════════════════════════════════════════════════════════════════════")
print("1) Detection Accuracy")
for key in ("A_no_defense", "B_detection_only", "C_full_defense"):
    m = metrics.get(key)
    if not m:
        print(f"  {key}: N/A")
        continue
    lat = "N/A" if m["detection_latency_ms"] is None else f'{m["detection_latency_ms"]:.2f} ms'
    cov = "N/A" if m["detection_coverage"] is None else f'{m["detection_coverage"]*100:.2f}%'
    det = "N/A" if m["malicious_detected"] is None else f'{m["malicious_detected"]}/{m["malicious_total"]}'
    print(f"  {key}: detection_latency={lat}, malicious_identified={det}, detection_coverage={cov}")

print("")
print("2) Network Availability")
for key in ("A_no_defense", "B_detection_only", "C_full_defense"):
    m = metrics.get(key)
    if not m:
        continue
    print(f"  {key}: success_rate={m['success_rate']*100:.2f}%, avg_delay={m['avg_delay_ms']:.2f} ms, failed={m['n_failed']}")

print("")
print("3) Cost Efficiency (vs A_no_defense)")
for key in ("B_detection_only", "C_full_defense"):
    m = metrics.get(key)
    if not m:
        continue
    pf = m.get("prevented_failures_vs_a")
    pd = m.get("prevented_damage_msat_vs_a")
    ce = m.get("cost_efficiency_msat_per_credit")
    ce_text = "N/A" if ce is None else f"{ce:.2f} msat/credit"
    print(
        f"  {key}: monitors(active={m['num_monitors']}, cumulative={m['cumulative_monitors']}), movement_budget={m['movement_budget_credits']} credits, "
        f"prevented_failures={pf}, prevented_damage={pd:.2f} msat, efficiency={ce_text}"
    )

out_csv = os.path.join(output_base, "evaluation_metrics.csv")
fieldnames = [
    "scenario", "success_rate", "avg_delay_ms", "n_failed", "total_attacks_triggered",
    "detection_latency_ms", "malicious_detected", "malicious_total", "detection_coverage",
    "num_monitors", "cumulative_monitors", "movement_credit_limit", "movement_budget_credits",
    "prevented_failures_vs_a", "prevented_damage_msat_vs_a", "cost_efficiency_msat_per_credit"
]
with open(out_csv, "w", newline="") as fp:
    writer = csv.DictWriter(fp, fieldnames=fieldnames)
    writer.writeheader()
    for key in ("A_no_defense", "B_detection_only", "C_full_defense"):
        m = metrics.get(key)
        if not m:
            continue
        writer.writerow({
            "scenario": m.get("scenario"),
            "success_rate": m.get("success_rate"),
            "avg_delay_ms": m.get("avg_delay_ms"),
            "n_failed": m.get("n_failed"),
            "total_attacks_triggered": m.get("total_attacks_triggered"),
            "detection_latency_ms": m.get("detection_latency_ms"),
            "malicious_detected": m.get("malicious_detected"),
            "malicious_total": m.get("malicious_total"),
            "detection_coverage": m.get("detection_coverage"),
            "num_monitors": m.get("num_monitors"),
            "cumulative_monitors": m.get("cumulative_monitors"),
            "movement_credit_limit": m.get("movement_credit_limit"),
            "movement_budget_credits": m.get("movement_budget_credits"),
            "prevented_failures_vs_a": m.get("prevented_failures_vs_a"),
            "prevented_damage_msat_vs_a": m.get("prevented_damage_msat_vs_a"),
            "cost_efficiency_msat_per_credit": m.get("cost_efficiency_msat_per_credit"),
        })
print("")
print(f"Saved: {out_csv}")
print("")
PYTHON
