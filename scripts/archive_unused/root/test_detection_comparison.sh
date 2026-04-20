#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPTDIR/cmake-build-debug"

echo "════════════════════════════════════════════════════════════════"
echo "攻撃検知・回避効果の比較テスト"
echo "Test: Attack Detection & Avoidance Effectiveness"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Payment count: 1000 (より統計的に有意な結果)"
echo ""

# Test 1: 攻撃のみ（監視なし、回避なし）
echo "【シナリオ 1】Attack Only (No monitoring, no avoidance)"
echo "攻撃: 15% malicious, 80% failure rate"
echo "防御: なし"
echo ""

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
malicious_node_ratio=0.15
malicious_failure_probability=0.8
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

mkdir -p result_attack_only
GSL_RNG_SEED=42 timeout 180 ./CLoTH_Gossip ./result_attack_only/ 2>&1 | tail -20

echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

# Test 2: 検知のみ（監視+レピュテーション、ただしルーティングは無視）
echo "【シナリオ 2】Detection Only (Monitoring + reputation, no avoidance in routing)"
echo "攻撃: 15% malicious, 80% failure rate"
echo "防御: 監視+レピュテーション追跡（ルーティングには使わない）"
echo ""

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
malicious_node_ratio=0.15
malicious_failure_probability=0.8
hub_degree_threshold=50
monitoring_strategy=method2
top_hub_count=30
enable_reputation_system=true
reputation_decay_rate=0.01
reputation_penalty_on_detection=0.3
reputation_recovery_rate=0.01
enable_monitor_movement=true
movement_credit_limit=5
enable_pra=false
enable_prt=false
prt_threshold=30
prt_abort_wait_time=1000
enable_rbr=false
rbr_reputation_weight=0.0
CONF

mkdir -p result_detection_only
GSL_RNG_SEED=42 timeout 180 ./CLoTH_Gossip ./result_detection_only/ 2>&1 | tail -20

echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

# Test 3: 検知+回避（完全防御）
echo "【シナリオ 3】Detection + Avoidance (Complete defense)"
echo "攻撃: 15% malicious, 80% failure rate"
echo "防御: 監視+レピュテーション+RBRルーティング回避"
echo ""

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
malicious_node_ratio=0.15
malicious_failure_probability=0.8
hub_degree_threshold=50
monitoring_strategy=method2
top_hub_count=30
enable_reputation_system=true
reputation_decay_rate=0.01
reputation_penalty_on_detection=0.3
reputation_recovery_rate=0.01
enable_monitor_movement=true
movement_credit_limit=5
enable_pra=true
enable_prt=true
prt_threshold=30
prt_abort_wait_time=1000
enable_rbr=true
rbr_reputation_weight=10.0
CONF

mkdir -p result_full_defense
GSL_RNG_SEED=42 timeout 180 ./CLoTH_Gossip ./result_full_defense/ 2>&1 | tail -20

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Comparison Analysis"
echo "════════════════════════════════════════════════════════════════"
echo ""

cd "$SCRIPTDIR"

python3 << 'PYTHON'
import csv
import os

scenarios = [
    ("Scenario 1: Attack Only", "cmake-build-debug/result_attack_only/baseline_metrics.csv"),
    ("Scenario 2: Detection Only", "cmake-build-debug/result_detection_only/baseline_metrics.csv"),
    ("Scenario 3: Detection + Avoidance", "cmake-build-debug/result_full_defense/baseline_metrics.csv"),
]

print()
print("┌" + "─" * 76 + "┐")
print("│ 攻撃検知・回避効果の比較 (1000 payments)".ljust(77) + "│")
print("├" + "─" * 76 + "┤")

results = []
for name, filepath in scenarios:
    try:
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            row = next(reader)
            results.append((name, row))
    except Exception as e:
        print(f"│ Error reading {filepath}: {e}".ljust(77) + "│")

# Display comparison table
print("│" + " " * 76 + "│")
print("│ " + f"{'Scenario':<45} {'Success Rate':<14} {'Delay':<13}" + "│")
print("├" + "─" * 76 + "┤")

for name, row in results:
    success = float(row['success_rate'])
    delay = float(row['avg_delay'])
    attacks = int(row['total_attacks_triggered'])
    
    print("│ " + f"{name:<45} {success:>7.2%}          {delay:>7.1f}ms" + " │")
    print("│ " + f"  Attacks: {attacks}".ljust(76) + "│")

print("├" + "─" * 76 + "┤")

# Calculate improvements
attack_only_rate = float(results[0][1]['success_rate'])
detection_only_rate = float(results[1][1]['success_rate'])
full_defense_rate = float(results[2][1]['success_rate'])

print("│ " + "効果分析 (Analysis):".ljust(76) + "│")
print("│" + " " * 76 + "│")

if detection_only_rate > attack_only_rate:
    improvement = (detection_only_rate - attack_only_rate) * 100
    print("│ " + f"  検知のみの効果: +{improvement:.2f}% (Detection tracking effect)".ljust(76) + "│")
else:
    print("│ " + f"  検知のみの効果: {(detection_only_rate - attack_only_rate)*100:+.2f}% (No routing integration)".ljust(76) + "│")

if full_defense_rate > detection_only_rate:
    improvement = (full_defense_rate - detection_only_rate) * 100
    print("│ " + f"  回避の追加効果: +{improvement:.2f}% (Avoidance routing effect)".ljust(76) + "│")
else:
    print("│ " + f"  回避の追加効果: {(full_defense_rate - detection_only_rate)*100:+.2f}% (Limited by sampling)".ljust(76) + "│")

if full_defense_rate > attack_only_rate:
    total_improvement = (full_defense_rate - attack_only_rate) * 100
    print("│ " + f"  完全防御の総効果: +{total_improvement:.2f}% (Total defense effect)".ljust(76) + "│")
else:
    print("│ " + f"  完全防御の総効果: {(full_defense_rate - attack_only_rate)*100:+.2f}%".ljust(76) + "│")

print("│" + " " * 76 + "│")
print("└" + "─" * 76 + "┘")

# Detailed statistics
print()
print("📊 詳細統計 (Detailed Statistics):")
print()
for name, row in results:
    print(f"{name}")
    print(f"  成功: {row['n_successful']}/{row['n_payments']}")
    print(f"  失敗: {row['n_failed']}")
    print(f"  攻撃検知: {row['total_attacks_triggered']} 件")
    print(f"  平均遅延: {row['avg_delay']} ms")
    print()

PYTHON
