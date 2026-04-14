# OMNeT++ Payment Network Attack Simulation

OMNeT++を使用した送金遅延シミュレーションです。ネットワーク攻撃（DDoS）がPayment Channel Network上の送金時間に与える影響を測定します。

## 構成

- `src/PaymentNode.h/cc` - 支払いノード（攻撃検出・遅延計測）
- `src/AttackGenerator.h/cc` - 攻撃生成モジュール
- `src/network_attack.ned` - ネットワークトポロジ定義
- `omnetpp.ini` - シミュレーション設定（複数シナリオ）
- `scripts/aggregate_results.py` - 結果集約・統計

## 出力ファイル

各ノードの計測結果:
```
result/attack_delays_node_0.csv
result/attack_delays_node_1.csv
...
```

結合されたサマリー:
```
result/attack_delays_summary.csv
result/attack_statistics.txt
```

## CSV カラム

| カラム | 説明 |
|--------|------|
| payment_id | 支払いID |
| sender_id | 送金元ノードID |
| receiver_id | 受取人ノードID |
| amount | 送金額（msat） |
| start_time | 開始時刻（秒） |
| end_time | 終了時刻（秒） |
| normal_delay | 通常の遅延（ms） |
| actual_delay | 実際の遅延（ms） |
| delay_increase | 遅延増加量（ms） |
| under_attack | 攻撃中フラグ（0/1） |
| attack_intensity | 攻撃強度（%） |
| attack_type | 攻撃種別（ddos等） |

## シミュレーション実行

### ビルド
```bash
cd omnetpp_sim
make
```

### 実行シナリオ

NoAttack - ベースラインシナリオ（攻撃なし）
```bash
./run -c NoAttack
```

LightAttack - 軽度の攻撃（30秒-60秒、強度1.5x）
```bash
./run -c LightAttack
```

MediumAttack - 中程度の攻撃（30秒-60秒、強度2.0x）
```bash
./run -c MediumAttack
```

HeavyAttack - 激烈な攻撃（30秒-60秒、強度3.0x）
```bash
./run -c HeavyAttack
```

SustainedAttack - 継続的攻撃（1秒-120秒、強度1.8x）
```bash
./run -c SustainedAttack
```

### 結果の集約
```bash
cd result
python3 ../scripts/aggregate_results.py .
```

## パラメータ調整

`omnetpp.ini` で以下をカスタマイズ可能:
- `numNodes` - ネットワークノード数
- `linkDelay` - リンク遅延
- `attackStartTime` - 攻撃開始時刻
- `attackDuration` - 攻撃継続時間
- `attackIntensity` - 攻撃強度乗数（1.0=no attack）
- `sim-time-limit` - シミュレーション総時間

## 分析方法

1. 複数シナリオを実行
2. `aggregate_results.py` で結果を集約
3. `attack_statistics.txt` で統計分析
4. `attack_delays_summary.csv` をデータ分析ツール（R/Python/Excel）で可視化

## 注釈

- 攻撃中は遅延が指数関数的に増加
- 各ノードが独立して結果を出力
- 攻撃強度は乗数で表現（1.5 = 50%増加）
