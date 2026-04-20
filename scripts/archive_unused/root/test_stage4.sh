#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPTDIR/cmake-build-debug"

echo "=========================================="
echo "Stage ④ Comprehensive Testing"
echo "=========================================="

# Test 1: Baseline (no malicious, no defenses)
echo ""
echo "[Test 1] Baseline: No malicious nodes"
cat > cloth_input.txt << 'EOF'
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
n_payments=300
average_payment_amount=100
variance_payment_amount=10
average_max_fee_limit=-1
variance_max_fee_limit=-1
enable_fake_balance_update=false
cul_threshold_dist_alpha=2
cul_threshold_dist_beta=10
mpp=1
malicious_node_ratio=0.0
malicious_failure_probability=0.0
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
EOF

mkdir -p result_baseline
GSL_RNG_SEED=42 timeout 120 ./CLoTH_Gossip ./result_baseline/ 2>&1 | tail -15

# Test 2: Attack (15% malicious, no defenses)
echo ""
echo "[Test 2] Attack: 15% malicious nodes, no defenses"
cat > cloth_input.txt << 'EOF'
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
n_payments=300
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
EOF

mkdir -p result_attack
GSL_RNG_SEED=42 timeout 120 ./CLoTH_Gossip ./result_attack/ 2>&1 | tail -15

# Test 3: Defense (15% malicious + PRT + monitoring + reputation)
echo ""
echo "[Test 3] Defense: 15% malicious + PRT + monitoring + reputation"
cat > cloth_input.txt << 'EOF'
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
n_payments=300
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
EOF

mkdir -p result_defense
GSL_RNG_SEED=42 timeout 120 ./CLoTH_Gossip ./result_defense/ 2>&1 | tail -15

# Summarize results
echo ""
echo "=========================================="
echo "Summary of Results"
echo "=========================================="
echo ""
echo "Scenario 1: Baseline"
grep "success_rate" result_baseline/baseline_metrics.csv
echo ""
echo "Scenario 2: Attack (no defense)"
grep "success_rate" result_attack/baseline_metrics.csv
echo ""
echo "Scenario 3: Defense (PRT + RBR + monitoring)"
grep "success_rate" result_defense/baseline_metrics.csv
echo ""
