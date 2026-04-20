"""
attack系シナリオ（a/b/c/d/e）の比較サマリを1つのCSVにまとめるスクリプト。

利用ライブラリ（何をしているか / 使い方）:
- csv:
  - summary.csv を読み込み、attack_scenario_summary.csv を書き出す
- os:
  - 引数がディレクトリかCSVかを判定し、summary.csv のパスを組み立てる
- statistics:
  - 各メトリクスの平均値を計算する
- sys:
  - 実行引数（output_dir または summary.csv）を受け取る
- collections.defaultdict:
  - (routing_method, scenario) 単位の行グループを簡潔に集計する
"""

import csv
import os
import statistics
import sys
from collections import defaultdict


ATTACK_SCENARIOS = [
    "a_no_attack",
    "b_detection_only",
    "c_full_defense",
    "d_extreme_no_defense",
    "e_extreme_full_defense",
]

METRICS = [
    "success_rate",
    "fail_no_path_rate",
    "fail_no_alternative_path_rate",
    "retry_rate",
    "time/average",
    "fee/average",
]


def to_float(value):
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (ValueError, TypeError):
        return None


def extract_scenario(simulation_id):
    wrapped = "/" + simulation_id.strip("/") + "/"
    for scenario in ATTACK_SCENARIOS:
        if f"/{scenario}/" in wrapped:
            return scenario
    return None


def avg(values):
    filtered = [v for v in values if v is not None]
    if not filtered:
        return ""
    return statistics.mean(filtered)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/summarize_attack4.py <output_dir_or_summary_csv>")
        sys.exit(1)

    input_path = sys.argv[1]
    summary_csv = input_path
    if os.path.isdir(input_path):
        summary_csv = os.path.join(input_path, "summary.csv")

    if not os.path.exists(summary_csv):
        print(f"ERROR: summary.csv not found: {summary_csv}")
        sys.exit(1)

    output_dir = os.path.dirname(summary_csv)
    by_method_scenario = defaultdict(list)
    by_scenario = defaultdict(list)
    methods = set()

    with open(summary_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            method = row.get("#param/routing_method", "")
            methods.add(method)

            scenario = extract_scenario(row.get("simulation_id", ""))
            if scenario is None:
                continue

            by_method_scenario[(method, scenario)].append(row)
            by_scenario[scenario].append(row)

    summary_path = os.path.join(output_dir, "attack_scenario_summary.csv")
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["routing_method", "scenario", "n"] + [f"{m}/mean" for m in METRICS]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for method in sorted(methods):
            for scenario in ATTACK_SCENARIOS:
                rows = by_method_scenario.get((method, scenario), [])
                out = {
                    "routing_method": method,
                    "scenario": scenario,
                    "n": len(rows),
                }
                for metric in METRICS:
                    out[f"{metric}/mean"] = avg([to_float(r.get(metric)) for r in rows])
                writer.writerow(out)

        for scenario in ATTACK_SCENARIOS:
            rows = by_scenario.get(scenario, [])
            out = {
                "routing_method": "ALL",
                "scenario": scenario,
                "n": len(rows),
            }
            for metric in METRICS:
                out[f"{metric}/mean"] = avg([to_float(r.get(metric)) for r in rows])
            writer.writerow(out)

    print(f"Wrote: {summary_path}")


if __name__ == "__main__":
    main()
