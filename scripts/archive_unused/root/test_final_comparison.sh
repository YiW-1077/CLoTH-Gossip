#!/bin/bash

cd /Users/user/CLionProjects/CLoTH-Gossip/cmake-build-debug

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "最終テスト：検知・回避の効果実証"
echo "Final Test: Detection & Avoidance Effectiveness"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "✓ パラメータ: 15% malicious, 80% attack success, 1000 payments"
echo "✓ 比較: No Defense vs Optimized PRT (threshold=100)"
echo ""

# Test 1: No Defense
echo "【Test 1】No Defense (Baseline)"
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
malicious_failure_probability=0.80
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

mkdir -p result_final_baseline
GSL_RNG_SEED=123 timeout 180 ./CLoTH_Gossip ./result_final_baseline/ 2>&1 | tail -5

# Test 2: PRT with high threshold
echo ""
echo "【Test 2】PRT Defense (threshold=100, optimized)"
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
malicious_failure_probability=0.80
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
prt_threshold=100
prt_abort_wait_time=1000
enable_rbr=false
rbr_reputation_weight=0.0
CONF

mkdir -p result_final_prt
GSL_RNG_SEED=123 timeout 180 ./CLoTH_Gossip ./result_final_prt/ 2>&1 | tail -5

echo ""
echo "════════════════════════════════════════════════════════════════════"

cd /Users/user/CLionProjects/CLoTH-Gossip

python3 << 'PYTHON'
import csv

print("\n┌─────────────────────────────────────────────────────────────────┐")
print("│ 最終テスト結果 (15% malicious, 80% attack, 1000 payments)       │")
print("├─────────────────────────────────────────────────────────────────┤")

scenarios = [
    ("No Defense", "cmake-build-debug/result_final_baseline/baseline_metrics.csv"),
    ("PRT (t=100)", "cmake-build-debug/result_final_prt/baseline_metrics.csv"),
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
            print(f"│ {name:15} | Success: {success:6.2%} | Attacks: {attacks:4} | Delay: {delay:6.1f}ms │")
    except Exception as e:
        print(f"│ Error: {e}")

if len(results) == 2:
    no_def_rate = float(results[0][1]['success_rate'])
    prt_rate = float(results[1][1]['success_rate'])
    improvement = (prt_rate - no_def_rate) * 100
    no_def_delay = float(results[0][1]['avg_delay'])
    prt_delay = float(results[1][1]['avg_delay'])
    delay_change = ((prt_delay - no_def_delay) / no_def_delay * 100)
    
    print(f"├─────────────────────────────────────────────────────────────────┤")
    print(f"│ PRT効果: {improvement:+.2f}% (成功率改善)".ljust(62) + "│")
    print(f"│ 遅延変化: {delay_change:+.1f}% (再構築による増加)".ljust(62) + "│")

# PRT統計
try:
    with open("cmake-build-debug/result_final_prt/prt_statistics.csv") as f:
        rows = list(csv.DictReader(f))
        aborted = sum(1 for r in rows if int(r['prt_abort_triggered']))
        recon_counts = [int(r['reconstruction_count']) for r in rows]
        avg_recon = sum(recon_counts) / len(recon_counts)
        
        print(f"│                                                               │")
        print(f"│ PRT統計:                                                      │")
        print(f"│  PRT中止: {aborted} 件 (threshold=100)".ljust(62) + "│")
        print(f"│  平均再構築: {avg_recon:.2f} (per payment)".ljust(62) + "│")
except:
    pass

print("└─────────────────────────────────────────────────────────────────┘\n")

PYTHON
