#!/usr/bin/env python3
"""
OMNeT++ Attack Simulation Results Aggregator
Combines results from individual node CSV files into a unified analysis
"""

import os
import glob
import pandas as pd
import sys
from pathlib import Path

def aggregate_attack_results(result_dir):
    """Aggregate CSV files from all nodes into a single analysis"""
    
    # Find all node result files
    node_files = sorted(glob.glob(os.path.join(result_dir, "attack_delays_node_*.csv")))
    
    if not node_files:
        print(f"Error: No attack delay files found in {result_dir}")
        return None
    
    all_payments = []
    
    # Read and combine all node results
    for node_file in node_files:
        try:
            df = pd.read_csv(node_file)
            all_payments.append(df)
        except Exception as e:
            print(f"Warning: Could not read {node_file}: {e}")
    
    if not all_payments:
        print("Error: No valid CSV files found")
        return None
    
    combined_df = pd.concat(all_payments, ignore_index=True)
    
    # Write combined results
    output_file = os.path.join(result_dir, "attack_delays_summary.csv")
    combined_df.to_csv(output_file, index=False)
    print(f"✓ Combined results: {output_file}")
    
    # Calculate statistics
    stats_file = os.path.join(result_dir, "attack_statistics.txt")
    with open(stats_file, 'w') as f:
        f.write("=== OMNeT++ Payment Delay Analysis Under Attack ===\n\n")
        
        # Overall statistics
        f.write("OVERALL STATISTICS\n")
        f.write(f"Total payments: {len(combined_df)}\n")
        f.write(f"Payments under attack: {combined_df['under_attack'].sum()}\n")
        f.write(f"Normal payments: {len(combined_df) - combined_df['under_attack'].sum()}\n\n")
        
        # Delay analysis
        f.write("DELAY ANALYSIS (milliseconds)\n")
        f.write(f"Average normal delay: {combined_df['normal_delay'].mean():.4f}ms\n")
        f.write(f"Average actual delay: {combined_df['actual_delay'].mean():.4f}ms\n")
        f.write(f"Average delay increase: {combined_df['delay_increase'].mean():.4f}ms\n")
        f.write(f"Max delay increase: {combined_df['delay_increase'].max():.4f}ms\n")
        f.write(f"Min delay increase: {combined_df['delay_increase'].min():.4f}ms\n\n")
        
        # Attack statistics
        if combined_df['under_attack'].sum() > 0:
            attack_df = combined_df[combined_df['under_attack'] == 1]
            f.write("UNDER ATTACK STATISTICS\n")
            f.write(f"Average delay during attack: {attack_df['actual_delay'].mean():.4f}ms\n")
            f.write(f"Average delay increase during attack: {attack_df['delay_increase'].mean():.4f}ms\n")
            f.write(f"Delay increase ratio: {(attack_df['actual_delay'].mean() / combined_df[combined_df['under_attack'] == 0]['actual_delay'].mean()):.2f}x\n\n")
        
        # Attack types
        f.write("ATTACK TYPES\n")
        attack_types = combined_df['attack_type'].value_counts()
        for attack_type, count in attack_types.items():
            f.write(f"{attack_type}: {count} payments\n")
        
        f.write("\n=== END OF ANALYSIS ===\n")
    
    print(f"✓ Statistics: {stats_file}")
    
    # Display summary to stdout
    print("\n" + "="*50)
    print("PAYMENT DELAY ANALYSIS - NETWORK UNDER ATTACK")
    print("="*50)
    print(f"Total payments analyzed: {len(combined_df)}")
    print(f"Payments under attack: {combined_df['under_attack'].sum()}")
    print(f"\nDelay Impact:")
    print(f"  Normal delay:       {combined_df['normal_delay'].mean():.4f} ms")
    print(f"  Actual delay:       {combined_df['actual_delay'].mean():.4f} ms")
    print(f"  Average increase:   {combined_df['delay_increase'].mean():.4f} ms")
    
    if combined_df['under_attack'].sum() > 0:
        attack_df = combined_df[combined_df['under_attack'] == 1]
        normal_df = combined_df[combined_df['under_attack'] == 0]
        print(f"\nAttack Impact Ratio: {(attack_df['actual_delay'].mean() / normal_df['actual_delay'].mean()):.2f}x")
    
    print("="*50)
    
    return combined_df

if __name__ == "__main__":
    result_dir = sys.argv[1] if len(sys.argv) > 1 else "result"
    aggregate_attack_results(result_dir)
