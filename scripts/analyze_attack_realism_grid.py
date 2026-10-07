#!/usr/bin/env python3
"""攻撃モデル現実化グリッド (run_attack_realism_grid.sh) の解析。

出力:
  1. 検出率ピボット (行=攻撃ノード割合, 列=分布) を n ごとに
  2. 検出の分母/分子の実数 (低割合セルで分母が1桁になり量子化する点を明示)
  3. per-node 診断: 悪意ノードの settle 異常率と settle_baseline_mean のドリフト
     → ばらつき導入で「サンプルが閾値未満」なのか「baseline が汚染されて閾値が
        上がった」のかを分離する (sub-threshold な保持は正常として baseline に入る)。
Usage: python3 scripts/analyze_attack_realism_grid.py <grid_dir>
"""
import csv
import os
import statistics as st
import sys


def read_grid(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def fnum(v, default=float("nan")):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def per_node_diag(cell_dir):
    """悪意ノードの settle 検定統計を集計する。"""
    rep = os.path.join(cell_dir, "reputation_dynamics.csv")
    if not os.path.exists(rep):
        return None
    tested, anom, base, deg, flagged = [], [], [], [], 0
    with open(rep) as f:
        for r in csv.DictReader(f):
            if r["is_malicious"] != "1":
                continue
            tc = fnum(r["settle_test_count"], 0)
            if tc <= 0:
                continue
            tested.append(tc)
            anom.append(fnum(r["settle_anomaly_count"], 0) / tc)
            bm = fnum(r["settle_baseline_mean"], 0)
            if bm > 0:
                base.append(bm)
            deg.append(fnum(r["degree"], 0))
            if fnum(r["malicious_reports"], 0) > 0:
                flagged += 1
    if not tested:
        return None
    return {
        "n_tested_nodes": len(tested),
        "tests_per_node": st.median(tested),
        "anomaly_rate": st.mean(anom),
        "baseline_mean": st.mean(base) if base else float("nan"),
        "median_degree": st.median(deg),
        "flagged": flagged,
    }


def main():
    grid_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/realism_grid"
    rows = read_grid(os.path.join(grid_dir, "results_grid.csv"))
    dists = sorted({r["dist"] for r in rows}, key=lambda d: ["fixed", "lognormal", "exponential", "pareto", "uniform"].index(d))
    ratios = sorted({r["malicious_ratio"] for r in rows}, key=float, reverse=True)
    ns = sorted({r["n_payments"] for r in rows}, key=int)

    def cell(d, ra, n):
        for r in rows:
            if r["dist"] == d and r["malicious_ratio"] == ra and r["n_payments"] == n:
                return r
        return None

    for metric, label, key in [
        ("検出率[%]", "detection_rate_pct", "detection_rate_pct"),
        ("precision[%]", "precision_pct", "precision_pct"),
    ]:
        for n in ns:
            print(f"\n=== {metric}  (n_payments={n}) ===")
            print("攻撃者割合 | " + " | ".join(f"{d:>12s}" for d in dists))
            for ra in ratios:
                vals = []
                for d in dists:
                    c = cell(d, ra, n)
                    vals.append(f"{fnum(c[key]):12.1f}" if c else f"{'-':>12s}")
                print(f"{ra:>10s} | " + " | ".join(vals))

    print("\n=== 検出の分子/分母 (detected / observable_attacked, 総悪意ノード数) ===")
    print(f"{'dist':<12s}{'ratio':>7s}{'n':>7s}{'malicious':>11s}{'observable':>12s}{'detected':>10s}{'FP':>5s}{'rate%':>8s}")
    for d in dists:
        for ra in ratios:
            for n in ns:
                c = cell(d, ra, n)
                if not c:
                    continue
                print(f"{d:<12s}{ra:>7s}{n:>7s}{c['total_malicious']:>11s}"
                      f"{c['observable_attacked']:>12s}{c['detected_attackers']:>10s}"
                      f"{c['false_positives']:>5s}{fnum(c['detection_rate_pct']):>8.1f}")

    print("\n=== per-node 診断 (悪意ノードの settle 検定) ===")
    print("baseline_mean は log(ms+1)。fixed=log(101)=4.615 付近が未汚染、上昇=sub-threshold 保持の学習")
    print(f"{'dist':<12s}{'ratio':>7s}{'n':>7s}{'tested':>8s}{'tests/node':>11s}"
          f"{'anomaly率':>11s}{'baseline':>10s}{'中央次数':>9s}{'flagged':>8s}")
    for d in dists:
        for ra in ratios:
            for n in ns:
                cd = os.path.join(grid_dir, f"dist={d}", f"ratio={ra}", f"n={n}")
                diag = per_node_diag(cd)
                if not diag:
                    continue
                print(f"{d:<12s}{ra:>7s}{n:>7s}{diag['n_tested_nodes']:>8d}"
                      f"{diag['tests_per_node']:>11.0f}{diag['anomaly_rate']:>11.3f}"
                      f"{diag['baseline_mean']:>10.3f}{diag['median_degree']:>9.0f}{diag['flagged']:>8d}")

    print("\n=== 攻撃被害 (griefing 遅延) ===")
    print(f"{'dist':<12s}{'ratio':>7s}{'n':>7s}{'griefed':>9s}{'grief_delay_ms':>16s}{'avg_delay_ms':>14s}{'success%':>10s}")
    for d in dists:
        for ra in ratios:
            for n in ns:
                c = cell(d, ra, n)
                if not c:
                    continue
                print(f"{d:<12s}{ra:>7s}{n:>7s}{c['payments_griefed']:>9s}"
                      f"{c['grief_delay_total_ms']:>16s}{fnum(c['avg_delay_ms']):>14.1f}"
                      f"{fnum(c['success_rate_pct']):>10.2f}")


if __name__ == "__main__":
    main()
