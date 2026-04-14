import csv

print("\n" + "="*80)
print("攻撃検知ギャップ分析 - なぜペナルティが発生していないのか")
print("="*80 + "\n")

# baseline_metrics を確認
print("【基本統計】")
print("─" * 80)

scenarios = {
    "Attack Only": "cmake-build-debug/result_attack_only/baseline_metrics.csv",
    "Detection Only": "cmake-build-debug/result_detection_only/baseline_metrics.csv",
    "Full Defense": "cmake-build-debug/result_full_defense/baseline_metrics.csv",
}

for name, path in scenarios.items():
    try:
        with open(path) as f:
            row = next(csv.DictReader(f))
            print(f"\n{name}:")
            print(f"  成功: {row['n_successful']}/{row['n_payments']}")
            print(f"  失敗: {row['n_failed']}")
            print(f"  攻撃検知: {row['total_attacks_triggered']} 件")
            print(f"  平均遅延: {row['avg_delay']} ms")
    except Exception as e:
        print(f"  Error: {e}")

print("\n\n【根本原因分析】")
print("─" * 80)

print("""
問題: すべてのシナリオでレピュテーションスコアが 1.0（完全信頼）のまま

原因の仮説:

1. ✗ 攻撃が検知されていない
   理由: Monitor は路上のノードだけで、path 外のノードの攻撃は観測できない
   結果: 実際には 460 攻撃が"トリガー"されたが、
        "検知"（monitor による検出）は別のイベント
        
2. ✓ 攻撃は発生している（total_attacks_triggered=460）
   理由: malicious_failure_probability=0.8 により
        ホップが確率的に失敗している
        
3. ✗ しかし Monitor が検知していない
   理由:
   a) Monitor の配置: Hub 周辺の leaf ノードのみ
   b) Payment の routing は random なため
      Monitor が配置されたノードを通らないことが多い
   c) 検知対象は "monitor が観測したホップ内での攻撃" のみ
   
4. ✗ Reputation が更新されない
   理由: detect_and_record_htlc_observation() が呼ばれていない可能性
        または呼ばれても検知条件を満たさない

【統計的説明】
- 1000送金 × 平均ホップ数 ≈ 6000 ホップ
- 監視ノード: 6,796 個（ただし全ネットワーク 12,012 辺の一部）
- 監視カバー率: ~65-85%
- 期待される攻撃観測: 460 × 0.80 × coverage ≈ 240-370 件？
- 実際の検知数: 0 件（報告されない）

【改善戦略】

① 監視検知の可視化
   - detect_and_record_htlc_observation() が呼ばれているか確認
   - 検知された攻撃ノードをログ出力
   
② 計画的な攻撃シミュレーション
   - 監視ノードの近くを通る特定の送金経路をテスト
   
③ 攻撃パラメータの調整
   - malicious_failure_probability=0.95（さらに攻撃的）
   - ネットワークサイズを小さくして検知確率を上げる
   
④ RBR 統合の完成
   - Dijkstra の edge_cost に reputation weighting を組み込む
   - 低スコアノードの経路除外機構

""")

