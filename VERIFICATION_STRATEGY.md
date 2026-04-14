# 防御メカニズム検証戦略

## 🔍 検証の段階

### Phase 1: メカニズム動作確認（Debug Logging）

**目的**: RBR・Detection が実際に呼び出されているか確認

#### 1.1 routing.c の RBR 計算
- Add logging to edge cost calculation (lines 580-608)
- Output: reputation_score, cost_multiplier, final_cost per edge

#### 1.2 htlc.c の Detection
- Add logging to detect_and_record_htlc_observation()
- Output: attack_detected, reputation_update, new_score

#### 1.3 Network topology analysis
- Calculate actual k-connectivity
- Find bottleneck nodes
- Verify Menger's theorem applies

---

### Phase 2: 結果の可視化

**出力**:
1. `reputation_timeline.csv` - 各ノードの reputation 時系列
2. `detection_events.csv` - 検知イベント・スコア更新の記録
3. `routing_analysis.csv` - Dijkstra 選択経路の reputation 分布

---

### Phase 3: 効果測定の改善

**現問題**: 99.50% という高い成功率では統計的有意差が出ない

**解決策**:
1. **協調攻撃**: 複数の悪意ノードを同一経路に配置
2. **ボトルネック攻撃**: 高度数ハブの周辺をターゲット化
3. **疎なネットワーク**: 冗長性を低く設定してテスト

---

## 📊 検証チェックリスト

### RBR 実装確認
- [ ] reputation_score が 1.0 以外の値に更新されるか
- [ ] cost_multiplier が適用されるか
- [ ] reputation < 0.3 時に LLONG_MAX が設定されるか

### Detection 実装確認
- [ ] detect_and_record_htlc_observation() が呼び出されるか
- [ ] update_node_reputation_on_detection() で -2x ペナルティ適用か
- [ ] Detection 数 vs 実際の攻撃数が合理的か

### 全体的な実装確認
- [ ] Global parameter 正しく初期化
- [ ] Dijkstra threads から global_net_params アクセス可能
- [ ] Reputation state が simulation 終了後に保存可能

---

## 🛠 実装プラン

1. Debug logging macro 追加
2. routing.c, htlc.c に logging 埋め込み
3. ビルド・テスト実行
4. ログ解析スクリプト作成
5. 結果を CSV export

---

## 📌 Key Questions to Answer

1. **Q**: Is detection firing at all?
   - Check: HTLC failure logs; reputation_score changes

2. **Q**: Is RBR cost multiplier actually reducing edge weights?
   - Check: Dijkstra cost calculation; path selection patterns

3. **Q**: Are attacks distributed randomly or clustered?
   - Check: Malicious node placement; attack pattern analysis

4. **Q**: Is 99.35% first-attempt success inherent to topology?
   - Check: Route diversity; bottleneck analysis

5. **Q**: Could coordination of attacks increase effectiveness?
   - Test: Same-path attack nodes vs. random placement
