#!/bin/bash
# Integration script: Run OMNeT++ attack simulation and incorporate results into CLoTH output
# Usage: run_with_attack_simulation.sh <seed> <output-directory> [cloth_settings...]

if [ $# -lt 3 ]; then
    echo "Usage: $0 <seed> <output-directory> <cloth_setting1=value1> [cloth_setting2=value2] ..."
    echo "Example: $0 42 /tmp/cloth-out n_payments=200 mpp=0"
    exit 1
fi

seed="$1"
output_dir="$2"
shift 2  # Remove first two args, keep cloth settings

mkdir -p "$output_dir/cloth"
mkdir -p "$output_dir/attack"

echo "===== Running CLoTH-Gossip Simulation ====="
# Run main CLoTH simulation
bash ./run-simulation.sh "$seed" "$output_dir/cloth" "$@"

echo ""
echo "===== Running OMNeT++ Attack Simulation ====="
# Run OMNeT++ attack simulation
cd omnetpp_sim || exit 1

# Configure attack scenario based on CLoTH parameters
attack_intensity=1.5
attack_start=30
attack_duration=30

# Create result directory
mkdir -p ../result_omnetpp
cd ../result_omnetpp || exit 1

# Run OMNeT++ with MediumAttack scenario
../omnetpp_sim/PaymentNetworkAttackSim -c MediumAttack > omnetpp.log 2>&1

echo "✓ OMNeT++ simulation completed"

echo ""
echo "===== Aggregating Results ====="
python3 ./scripts/aggregate_results.py . > /dev/null 2>&1

# Copy attack results to main output
cp attack_delays_summary.csv "$output_dir/attack/"
cp attack_statistics.txt "$output_dir/attack/"

echo ""
echo "===== Final Output Summary ====="
echo "CLoTH Results: $output_dir/cloth/"
echo "Attack Simulation: $output_dir/attack/"
echo ""
echo "Files generated:"
ls -lh "$output_dir/cloth/"*.csv 2>/dev/null | awk '{print "  " $9}'
ls -lh "$output_dir/attack/"*.csv "$output_dir/attack/"*.txt 2>/dev/null | awk '{print "  " $9}'
