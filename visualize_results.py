#!/usr/bin/env python3
"""
CLoTH-Gossip スイープシミュレーション結果の可視化
"""

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import numpy as np
import sys
from pathlib import Path

def load_results(csv_path):
    """結果CSVを読み込む"""
    df = pd.read_csv(csv_path)
    # メトリクスをfloatに変換（N/Aは0に置き換え）
    for col in ['success_rate', 'detection_rate', 'avg_delay', 'malicious_ratio']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    return df

def plot_monitor_percentage_effect(df, output_dir):
    """監視割合の効果を可視化"""
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('監視割合の効果（支払額別・ノード数別）', fontsize=16, fontweight='bold')
    
    payment_amounts = sorted(df['payment_amount_msat'].unique())
    node_counts = sorted(df['node_count'].unique())
    
    # 支払額ごとにプロット
    for idx, payment_amt in enumerate(payment_amounts):
        ax = axes.flatten()[idx]
        
        for nodes in node_counts:
            subset = df[(df['payment_amount_msat'] == payment_amt) & 
                       (df['node_count'] == nodes)].sort_values('monitor_percentage')
            
            if len(subset) > 0:
                ax.plot(subset['monitor_percentage'], subset['success_rate'], 
                       marker='o', label=f'{nodes} nodes', linewidth=2)
        
        ax.set_xlabel('Monitor Percentage (%)', fontsize=11)
        ax.set_ylabel('Success Rate', fontsize=11)
        ax.set_title(f'Payment Amount: {payment_amt} msat', fontsize=12, fontweight='bold')
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_ylim([0, 1.0])
    
    # 4番目のサブプロット：検出率
    ax = axes.flatten()[3]
    for nodes in node_counts:
        subset = df[(df['payment_amount_msat'] == payment_amounts[0]) & 
                   (df['node_count'] == nodes)].sort_values('monitor_percentage')
        
        if len(subset) > 0:
            ax.plot(subset['monitor_percentage'], subset['detection_rate'], 
                   marker='s', label=f'{nodes} nodes', linewidth=2)
    
    ax.set_xlabel('Monitor Percentage (%)', fontsize=11)
    ax.set_ylabel('Detection Rate', fontsize=11)
    ax.set_title(f'Detection Rate (Payment: {payment_amounts[0]} msat)', fontsize=12, fontweight='bold')
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_ylim([0, 1.0])
    
    plt.tight_layout()
    output_path = Path(output_dir) / 'monitor_percentage_effect.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"✓ Saved: {output_path}")
    plt.close()

def plot_payment_amount_effect(df, output_dir):
    """支払額の効果を可視化"""
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('支払額の効果（ノード数別・監視割合別）', fontsize=16, fontweight='bold')
    
    node_counts = sorted(df['node_count'].unique())
    monitor_pcts = [5, 15, 25, 35]  # 代表的な監視割合
    
    for idx, nodes in enumerate(node_counts):
        ax = axes.flatten()[idx]
        
        for monitor_pct in monitor_pcts:
            subset = df[(df['node_count'] == nodes) & 
                       (df['monitor_percentage'] == monitor_pct)].sort_values('payment_amount_msat')
            
            if len(subset) > 0:
                ax.plot(subset['payment_amount_msat'], subset['success_rate'], 
                       marker='o', label=f'{monitor_pct}% monitors', linewidth=2)
        
        ax.set_xlabel('Payment Amount (msat)', fontsize=11)
        ax.set_ylabel('Success Rate', fontsize=11)
        ax.set_title(f'Nodes: {nodes}', fontsize=12, fontweight='bold')
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_xscale('log')
        ax.set_ylim([0, 1.0])
    
    plt.tight_layout()
    output_path = Path(output_dir) / 'payment_amount_effect.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"✓ Saved: {output_path}")
    plt.close()

def plot_node_scale_effect(df, output_dir):
    """ノード規模の効果を可視化"""
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    fig.suptitle('ノード規模の効果（監視割合別・支払額別）', fontsize=16, fontweight='bold')
    
    payment_amounts = sorted(df['payment_amount_msat'].unique())
    
    for idx, payment_amt in enumerate(payment_amounts):
        ax = axes[idx]
        
        for monitor_pct in [5, 20, 35, 50]:
            subset = df[(df['payment_amount_msat'] == payment_amt) & 
                       (df['monitor_percentage'] == monitor_pct)].sort_values('node_count')
            
            if len(subset) > 0:
                ax.plot(subset['node_count'], subset['success_rate'], 
                       marker='o', label=f'{monitor_pct}% monitors', linewidth=2)
        
        ax.set_xlabel('Number of Nodes', fontsize=11)
        ax.set_ylabel('Success Rate', fontsize=11)
        ax.set_title(f'Payment Amount: {payment_amt} msat', fontsize=12, fontweight='bold')
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_ylim([0, 1.0])
    
    plt.tight_layout()
    output_path = Path(output_dir) / 'node_scale_effect.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"✓ Saved: {output_path}")
    plt.close()

def plot_heatmap(df, output_dir):
    """監視割合 vs ノード数のヒートマップ"""
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    fig.suptitle('成功率 - 監視割合 vs ノード数（支払額別）', fontsize=16, fontweight='bold')
    
    payment_amounts = sorted(df['payment_amount_msat'].unique())
    
    for idx, payment_amt in enumerate(payment_amounts):
        ax = axes[idx]
        
        # ピボットテーブル作成
        subset = df[df['payment_amount_msat'] == payment_amt]
        pivot = subset.pivot_table(values='success_rate', 
                                   index='node_count', 
                                   columns='monitor_percentage')
        
        # ヒートマップ描画
        im = ax.imshow(pivot.values, aspect='auto', cmap='RdYlGn', vmin=0, vmax=1)
        
        ax.set_xlabel('Monitor Percentage (%)', fontsize=11)
        ax.set_ylabel('Number of Nodes', fontsize=11)
        ax.set_title(f'Payment Amount: {payment_amt} msat', fontsize=12, fontweight='bold')
        
        # x軸・y軸ラベル
        ax.set_xticks(range(0, len(pivot.columns), 5))
        ax.set_xticklabels(pivot.columns[::5], rotation=45)
        ax.set_yticks(range(len(pivot.index)))
        ax.set_yticklabels(pivot.index)
        
        plt.colorbar(im, ax=ax, label='Success Rate')
    
    plt.tight_layout()
    output_path = Path(output_dir) / 'heatmap_success_rate.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"✓ Saved: {output_path}")
    plt.close()

def plot_summary_stats(df, output_dir):
    """統計サマリーを可視化"""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('統計サマリー', fontsize=16, fontweight='bold')
    
    # ノード数ごとの平均成功率
    ax = axes[0, 0]
    node_stats = df.groupby('node_count')['success_rate'].agg(['mean', 'std'])
    ax.bar(node_stats.index, node_stats['mean'], 
           yerr=node_stats['std'], capsize=5, alpha=0.7, color='steelblue')
    ax.set_xlabel('Number of Nodes', fontsize=11)
    ax.set_ylabel('Mean Success Rate', fontsize=11)
    ax.set_title('Success Rate by Node Count', fontsize=12, fontweight='bold')
    ax.set_ylim([0, 1.0])
    ax.grid(True, alpha=0.3, axis='y')
    
    # 支払額ごとの平均成功率
    ax = axes[0, 1]
    pmt_stats = df.groupby('payment_amount_msat')['success_rate'].agg(['mean', 'std'])
    ax.bar(range(len(pmt_stats)), pmt_stats['mean'], 
           yerr=pmt_stats['std'], capsize=5, alpha=0.7, color='coral')
    ax.set_xlabel('Payment Amount (msat)', fontsize=11)
    ax.set_ylabel('Mean Success Rate', fontsize=11)
    ax.set_title('Success Rate by Payment Amount', fontsize=12, fontweight='bold')
    ax.set_xticks(range(len(pmt_stats)))
    ax.set_xticklabels(pmt_stats.index)
    ax.set_ylim([0, 1.0])
    ax.grid(True, alpha=0.3, axis='y')
    
    # 監視割合ごとの平均成功率
    ax = axes[1, 0]
    monitor_stats = df.groupby('monitor_percentage')['success_rate'].mean()
    ax.plot(monitor_stats.index, monitor_stats.values, marker='o', 
           linewidth=2, markersize=4, color='green')
    ax.fill_between(monitor_stats.index, monitor_stats.values, alpha=0.3, color='green')
    ax.set_xlabel('Monitor Percentage (%)', fontsize=11)
    ax.set_ylabel('Mean Success Rate', fontsize=11)
    ax.set_title('Success Rate by Monitor Percentage', fontsize=12, fontweight='bold')
    ax.set_ylim([0, 1.0])
    ax.grid(True, alpha=0.3)
    
    # 検出率の分布
    ax = axes[1, 1]
    detection_by_monitor = df.groupby('monitor_percentage')['detection_rate'].mean()
    ax.plot(detection_by_monitor.index, detection_by_monitor.values, marker='s', 
           linewidth=2, markersize=4, color='purple')
    ax.fill_between(detection_by_monitor.index, detection_by_monitor.values, alpha=0.3, color='purple')
    ax.set_xlabel('Monitor Percentage (%)', fontsize=11)
    ax.set_ylabel('Mean Detection Rate', fontsize=11)
    ax.set_title('Detection Rate by Monitor Percentage', fontsize=12, fontweight='bold')
    ax.set_ylim([0, 1.0])
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    output_path = Path(output_dir) / 'summary_stats.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"✓ Saved: {output_path}")
    plt.close()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 visualize_results.py <results_csv> [output_dir]")
        print("\nExample:")
        print("  python3 visualize_results.py /path/to/results_summary.csv")
        print("  python3 visualize_results.py /path/to/results_summary.csv /path/to/output")
        print("\nDefault: Saves graphs in the same directory as results_summary.csv")
        sys.exit(1)
    
    csv_path = Path(sys.argv[1])
    # デフォルトでCSVの親ディレクトリに保存（タイムスタンプフォルダ内）
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else csv_path.parent
    
    if not csv_path.exists():
        print(f"ERROR: CSV file not found: {csv_path}")
        sys.exit(1)
    
    print(f"Loading results from: {csv_path}")
    df = load_results(str(csv_path))
    print(f"Loaded {len(df)} records")
    print(f"\nDataset statistics:")
    print(f"  Nodes: {sorted(df['node_count'].unique())}")
    print(f"  Payment amounts: {sorted(df['payment_amount_msat'].unique())}")
    print(f"  Monitor percentages: {df['monitor_percentage'].min()}~{df['monitor_percentage'].max()}%")
    print(f"  Status: {df['status'].value_counts().to_dict()}")
    
    print(f"\nGenerating visualizations...")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    plot_monitor_percentage_effect(df, output_dir)
    plot_payment_amount_effect(df, output_dir)
    plot_node_scale_effect(df, output_dir)
    plot_heatmap(df, output_dir)
    plot_summary_stats(df, output_dir)
    
    print(f"\n✓ All visualizations saved to: {output_dir}")

if __name__ == '__main__':
    main()
