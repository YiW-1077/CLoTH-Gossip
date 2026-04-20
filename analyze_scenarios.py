#!/usr/bin/env python3
"""
Analyze and compare 5-scenario attack simulation results
"""

import os
import sys
import csv
import json
from pathlib import Path
from collections import defaultdict

def parse_csv(filepath):
    """Parse CSV file and return list of dicts"""
    if not os.path.exists(filepath):
        return []
    
    data = []
    try:
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                data.append(row)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    
    return data

def analyze_payments(payments_csv):
    """Analyze payments_output.csv"""
    payments = parse_csv(payments_csv)
    if not payments:
        return None
    
    total = len(payments)
    successful = sum(1 for p in payments if p.get('is_succeeded', '0') == '1')
    failed = total - successful
    success_rate = (successful / total * 100) if total > 0 else 0
    
    # Calculate average attempts/delay
    attempts_sum = 0
    delays = []
    
    for p in payments:
        try:
            if 'attempts' in p:
                attempts_sum += int(p['attempts'])
        except:
            pass
    
    avg_attempts = (attempts_sum / total) if total > 0 else 0
    
    return {
        'total_payments': total,
        'successful': successful,
        'failed': failed,
        'success_rate': success_rate,
        'avg_attempts': avg_attempts
    }

def analyze_monitoring(monitoring_csv):
    """Analyze payment_information_estimation.csv"""
    data = parse_csv(monitoring_csv)
    if not data:
        return {'observations': 0, 'estimated_payments': 0}
    
    return {
        'observations': len(data),
        'estimated_payments': sum(1 for d in data if d.get('num_observations', '0') != '0')
    }

def analyze_monitors(monitor_csv):
    """Analyze monitor placement"""
    data = parse_csv(monitor_csv)
    if not data:
        return {'monitors_deployed': 0}
    
    return {'monitors_deployed': len(data)}

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_scenarios.py <output_root_directory>")
        sys.exit(1)
    
    output_root = sys.argv[1]
    if not os.path.isdir(output_root):
        print(f"Error: {output_root} not found")
        sys.exit(1)
    
    results = {}
    
    # Find all scenario directories
    scenario_dirs = sorted([d for d in os.listdir(output_root) if d.startswith('scenario_')])
    
    print("\n" + "="*70)
    print("5-SCENARIO ATTACK COMPARISON ANALYSIS")
    print("="*70)
    print(f"Base directory: {output_root}\n")
    
    for scenario_dir in scenario_dirs:
        scenario_path = os.path.join(output_root, scenario_dir)
        scenario_name = scenario_dir.replace('scenario_', '')
        
        print(f"\n{'='*70}")
        print(f"Scenario {scenario_name}")
        print(f"{'='*70}")
        
        # Analyze payments
        payments_csv = os.path.join(scenario_path, 'payments_output.csv')
        payment_stats = analyze_payments(payments_csv)
        
        if payment_stats:
            print(f"\nPayment Statistics:")
            print(f"  Total Payments: {payment_stats['total_payments']}")
            print(f"  Successful: {payment_stats['successful']}")
            print(f"  Failed: {payment_stats['failed']}")
            print(f"  Success Rate: {payment_stats['success_rate']:.2f}%")
            print(f"  Avg Attempts: {payment_stats['avg_attempts']:.2f}")
        
        # Analyze monitoring
        monitoring_csv = os.path.join(scenario_path, 'payment_information_estimation.csv')
        monitor_stats = analyze_monitoring(monitoring_csv)
        print(f"\nMonitoring Statistics:")
        print(f"  Observations: {monitor_stats['observations']}")
        print(f"  Estimated Payments: {monitor_stats['estimated_payments']}")
        
        # Analyze monitor placement
        monitor_csv = os.path.join(scenario_path, 'monitor_placement.csv')
        placement_stats = analyze_monitors(monitor_csv)
        print(f"\nMonitor Placement:")
        print(f"  Monitors Deployed: {placement_stats['monitors_deployed']}")
        
        # Store results
        results[scenario_name] = {
            'payments': payment_stats,
            'monitoring': monitor_stats,
            'placement': placement_stats
        }
    
    # Comparison summary
    print(f"\n\n{'='*70}")
    print("COMPARISON SUMMARY")
    print(f"{'='*70}\n")
    
    if 'A' in results and results['A']['payments']:
        baseline_success = results['A']['payments']['success_rate']
        print(f"Baseline (Scenario A) success rate: {baseline_success:.2f}%\n")
        
        for scenario in ['B', 'C', 'D', 'E']:
            if scenario in results and results[scenario]['payments']:
                success = results[scenario]['payments']['success_rate']
                diff = success - baseline_success
                print(f"Scenario {scenario}: {success:.2f}% (vs baseline: {diff:+.2f}%)")
    
    # Save JSON results
    results_file = os.path.join(output_root, 'comparison_results.json')
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n✅ Results saved to: {results_file}")

if __name__ == '__main__':
    main()
