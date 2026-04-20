#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPTDIR/cmake-build-debug"

echo "════════════════════════════════════════════════════════════════"
echo "極限攻撃テスト - 検知・回避効果の明確化"
echo "Extreme Attack Test - Visualizing Detection & Avoidance"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "✓ 攻撃パラメータ強化:"
echo "  - 悪意のあるノード: 25% (より多い)"
echo "  - 攻撃成功率: 95% (より高い)"
echo "  - 送金数: 1000"
echo ""

# Test 1: 攻撃のみ（防御なし）
echo "【Test 1】Extreme Attack (No defense)"
cat > cloth_input.txt << 'CONF'
generate_network_from_file=true
nodes_filename=nodes_ln.csv
channels_filename=channels_ln.csv
edges_filename=edges_ln.csv
n_additional_nodes=
n_channels_per_node=
capacity_per_channel=
faulty_node_probability=0.0
generate_payments_from_file=false
payment_timeout=60000
average_payment_forward_interval=100
variance_payment_forward_interval=1
routing_method=cloth_original
group_size=5
group_limit_rate=0.1
group_cap_update=true
group_broadcast_delay=0
payments_filename=
payment_rate=1
n_payments=1000
average_payment_amount=100
variance_payment_amount=10
average_max_fee_limit=-1
variance_max_fee_limit=-1
enable_fake_balance_update=false
cul_threshold_dist_alpha=2
cul_threshold_dist_beta=10
mpp=1
malicious_node_ratio=0.25
malicious_failure_probability=0.95
hub_degree_threshold=50
monitoring_strategy=method1
top_hub_count=30
enable_reputation_system=false
reputation_decay_rate=0.0
reputation_penalty_on_detection=0.0
reputation_recovery_rate=0.0
enable_monitor_movement=false
movement_credit_limit=0
enable_pra=false
enable_prt=false
prt_threshold=30
prt_abort_wait_time=1000
enable_rbr=false
rbr_reputation_weight=0.0
CONF

mkdir -p result_extreme_attack
GSL_RNG_SEED=42 timeout 180 ./CLoTH_Gossip ./result_extreme_attack/ 2>&1 | grep -E "(成功|失敗|成功率|遅延|攻撃|Wrote)" | tail -10

# Test 2: PRT防御のみ
echo ""
echo "【Test 2】Extreme Attack + PRT Defense (No monitoring)"
cat > cloth_input.txt << 'CONF'
generate_network_from_file=true
nodes_filename=nodes_ln.csv
channels_filename=channels_ln.csv
edges_filename=edges_ln.csv
n_additional_nodes=
n_channels_per_node=
capacity_per_channel=
faulty_node_probability=0.0
generate_payments_from_file=false
payment_timeout=60000
average_payment_forward_interval=100
variance_payment_forward_interval=1
routing_method=cloth_original
group_size=5
group_limit_rate=0.1
group_cap_update=true
group_broadcast_delay=0
payments_filename=
payment_rate=1
n_payments=1000
average_payment_amount=100
variance_payment_amount=10
average_max_fee_limit=-1
variance_max_fee_limit=-1
enable_fake_balance_update=false
cul_threshold_dist_alpha=2
cul_threshold_dist_beta=10
mpp=1
malicious_node_ratio=0.25
malicious_failure_probability=0.95
hub_degree_threshold=50
monitoring_strategy=method1
top_hub_count=30
enable_reputation_system=false
reputation_decay_rate=0.0
reputation_penalty_on_detection=0.0
reputation_recovery_rate=0.0
enable_monitor_movement=false
movement_credit_limit=0
enable_pra=true
enable_prt=true
prt_threshold=20
prt_abort_wait_time=1000
enable_rbr=false
rbr_reputation_weight=0.0
CONF

mkdir -p result_extreme_prt
GSL_RNG_SEED=42 timeout 180 ./CLoTH_Gossip ./result_extreme_prt/ 2>&1 | grep -E "(成功|失敗|成功率|遅延|攻撃|Wrote)" | tail -10

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "結果比較"
echo "════════════════════════════════════════════════════════════════"
echo ""

cd "$SCRIPTDIR"

python3 << 'PYTHON'
import csv

print("\n┌─────────────────────────────────────────────────────────────────┐")
print("│ 極限攻撃テスト結果 (25% malicious, 95% success rate)             │")
print("├─────────────────────────────────────────────────────────────────┤")

scenarios = [
    ("No Defense", "cmake-build-debug/result_extreme_attack/baseline_metrics.csv"),
    ("PRT Defense", "cmake-build-debug/result_extreme_prt/baseline_metrics.csv"),
]

results = []
for name, path in scenarios:
    try:
        with open(path) as f:
            row = next(csv.DictReader(f))
            results.append((name, row))
            success = float(row['success_rate'])
            attacks = int(row['total_attacks_triggered'])
            delay = float(row['avg_delay'])
            print(f"│ {name:20} | Success: {success:6.2%} | Attacks: {attacks:4} │")
    except Exception as e:
        print(f"│ Error: {e}")

if len(results) == 2:
    no_def_rate = float(results[0][1]['success_rate'])
    prt_rate = float(results[1][1]['success_rate'])
    improvement = (prt_rate - no_def_rate) * 100
    print(f"│                                                               │")
    print(f"│ PRT防御による改善: {improvement:+.2f}%".ljust(62) + "│")

print("└─────────────────────────────────────────────────────────────────┘\n")

PYTHON
