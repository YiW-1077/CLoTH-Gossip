#!/usr/bin/env python3
"""
attack_scenario_summary.csv から攻撃パラメータ比較グラフを生成する。

入力:
  - 実験出力ディレクトリ もしくは attack_scenario_summary.csv のパス

出力:
  - <output_dir>/plots/
      - attack_param_success_rate_heatmap.png
      - attack_param_delay_heatmap.png
      - attack_param_success_rate_lines.png
      - attack_param_delay_lines.png
      - attack_param_success_diff_full_vs_no_heatmap.png
      - attack_param_delay_diff_full_vs_no_heatmap.png
      - attack_param_success_lines_full_vs_no.png
      - attack_param_delay_lines_full_vs_no.png
"""

from __future__ import annotations

import csv
import os
import sys
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def to_float(value):
    try:
        if value is None or str(value).strip() == "":
            return None
        return float(value)
    except (ValueError, TypeError):
        return None


def col(row, *candidates):
    for key in candidates:
        if key in row:
            return row.get(key)
    return None


def read_rows(csv_path):
    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def aggregation_is_param(row):
    v = col(row, "集計レベル", "aggregation_level")
    return v in ("シナリオ×攻撃パラメータ集計", "scenario_by_attack_params")


def scenario_name(row):
    return col(row, "シナリオ", "scenario")


def routing_name(row):
    return col(row, "ルーティング方式", "routing_method")


def malicious_ratio(row):
    return to_float(col(row, "攻撃ノード割合", "malicious_node_ratio"))


def attack_success(row):
    return to_float(col(row, "攻撃成功確率", "malicious_failure_probability"))


def success_rate(row):
    return to_float(col(row, "成功率(平均)", "success_rate/mean"))


def avg_delay(row):
    return to_float(col(row, "実データ_平均支払い時間", "raw/avg_payment_time/mean"))


def avg_attempts(row):
    return to_float(col(row, "実データ_平均試行回数", "raw/avg_attempts/mean"))


def ensure_plot_dir(output_dir):
    plot_dir = os.path.join(output_dir, "plots")
    os.makedirs(plot_dir, exist_ok=True)
    return plot_dir


def build_heatmap_matrices(rows):
    pairs = []
    for r in rows:
        mr = malicious_ratio(r)
        ac = attack_success(r)
        sr = success_rate(r)
        dl = avg_delay(r)
        if None in (mr, ac, sr, dl):
            continue
        pairs.append((mr, ac, sr, dl))
    if not pairs:
        return [], [], [], []

    mrs = sorted({p[0] for p in pairs})
    acs = sorted({p[1] for p in pairs})
    sr_mat = [[None for _ in acs] for _ in mrs]
    dl_mat = [[None for _ in acs] for _ in mrs]

    for mr, ac, sr, dl in pairs:
        i = mrs.index(mr)
        j = acs.index(ac)
        sr_mat[i][j] = sr
        dl_mat[i][j] = dl
    return mrs, acs, sr_mat, dl_mat


def plot_heatmap(matrix, xvals, yvals, title, cbar_label, annotate_fmt, out_path):
    if not matrix:
        return
    safe = [[0 if v is None else v for v in row] for row in matrix]
    fig, ax = plt.subplots(figsize=(8, 5))
    im = ax.imshow(safe, aspect="auto", origin="lower")
    ax.set_title(title)
    ax.set_xlabel("Attack success probability")
    ax.set_ylabel("Malicious ratio")
    ax.set_xticks(range(len(xvals)))
    ax.set_xticklabels([f"{x:g}" for x in xvals])
    ax.set_yticks(range(len(yvals)))
    ax.set_yticklabels([f"{y:g}" for y in yvals])
    for i in range(len(yvals)):
        for j in range(len(xvals)):
            v = matrix[i][j]
            if v is not None:
                ax.text(j, i, format(v, annotate_fmt), ha="center", va="center", fontsize=8)
    fig.colorbar(im, ax=ax, label=cbar_label)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_lines_by_mr(rows, y_getter, title, y_label, out_path):
    by_mr = defaultdict(list)
    for r in rows:
        mr = malicious_ratio(r)
        ac = attack_success(r)
        y = y_getter(r)
        if None in (mr, ac, y):
            continue
        by_mr[mr].append((ac, y))

    if not by_mr:
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    for mr in sorted(by_mr.keys()):
        pts = sorted(by_mr[mr], key=lambda x: x[0])
        ax.plot([x for x, _ in pts], [y for _, y in pts], marker="o", label=f"malicious_ratio={mr:g}")
    ax.set_title(title)
    ax.set_xlabel("Attack success probability")
    ax.set_ylabel(y_label)
    ax.grid(alpha=0.25)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def pick_scenario_rows(rows, candidates):
    return [r for r in rows if scenario_name(r) in candidates]


def generate_defense_comparison(rows, plot_dir):
    param_rows = [r for r in rows if aggregation_is_param(r) and routing_name(r) == "ALL"]
    no_def = pick_scenario_rows(param_rows, ("無防御", "no_defense", "B: 検知のみ", "b_detection_only"))
    full_def = pick_scenario_rows(param_rows, ("C: フル防御", "c_full_defense", "full_defense"))
    if not no_def or not full_def:
        return

    def key_of(r):
        return malicious_ratio(r), attack_success(r)

    no_map = {key_of(r): r for r in no_def if None not in key_of(r)}
    fu_map = {key_of(r): r for r in full_def if None not in key_of(r)}
    common = sorted(set(no_map.keys()) & set(fu_map.keys()), key=lambda x: (x[0], x[1]))
    if not common:
        return

    mrs = sorted({k[0] for k in common})
    acs = sorted({k[1] for k in common})
    succ_diff = [[None for _ in acs] for _ in mrs]
    delay_diff = [[None for _ in acs] for _ in mrs]
    for i, mr in enumerate(mrs):
        for j, ac in enumerate(acs):
            n = no_map.get((mr, ac))
            d = fu_map.get((mr, ac))
            if n is None or d is None:
                continue
            sn, sd = success_rate(n), success_rate(d)
            tn, td = avg_delay(n), avg_delay(d)
            succ_diff[i][j] = (sd - sn) if None not in (sn, sd) else None
            delay_diff[i][j] = (td - tn) if None not in (tn, td) else None

    plot_heatmap(
        succ_diff,
        acs,
        mrs,
        "Success Rate Difference (Full - No defense)",
        "Delta Success Rate",
        "+.3f",
        os.path.join(plot_dir, "attack_param_success_diff_full_vs_no_heatmap.png"),
    )
    plot_heatmap(
        delay_diff,
        acs,
        mrs,
        "Delay Difference (Full - No defense)",
        "Delta Avg Delay",
        "+.0f",
        os.path.join(plot_dir, "attack_param_delay_diff_full_vs_no_heatmap.png"),
    )

    def plot_dual_lines(metric_getter, title, ylabel, out_name):
        fig, axes = plt.subplots(2, 3, figsize=(12, 7), sharex=True, sharey=True)
        axes = axes.flatten()
        for idx, mr in enumerate(mrs[:6]):
            ax = axes[idx]
            npts = sorted(
                [(k[1], metric_getter(no_map[k])) for k in common if k[0] == mr and metric_getter(no_map[k]) is not None],
                key=lambda x: x[0],
            )
            dpts = sorted(
                [(k[1], metric_getter(fu_map[k])) for k in common if k[0] == mr and metric_getter(fu_map[k]) is not None],
                key=lambda x: x[0],
            )
            ax.plot([x for x, _ in npts], [y for _, y in npts], marker="o", label="No defense")
            ax.plot([x for x, _ in dpts], [y for _, y in dpts], marker="o", label="Full defense")
            ax.set_title(f"malicious_ratio={mr:g}")
            ax.grid(alpha=0.25)
        for ax in axes:
            ax.set_xlabel("Attack success")
            ax.set_ylabel(ylabel)
        handles, labels = axes[0].get_legend_handles_labels()
        fig.legend(handles, labels, loc="upper center", ncol=2)
        fig.suptitle(title)
        fig.tight_layout(rect=(0, 0, 1, 0.94))
        fig.savefig(os.path.join(plot_dir, out_name), dpi=150)
        plt.close(fig)

    plot_dual_lines(success_rate, "Success Rate: Full vs No defense", "Success rate", "attack_param_success_lines_full_vs_no.png")
    plot_dual_lines(avg_delay, "Delay: Full vs No defense", "Avg payment time", "attack_param_delay_lines_full_vs_no.png")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/plot_attack_summary.py <output_dir_or_attack_scenario_summary_csv>")
        sys.exit(1)

    input_path = sys.argv[1]
    if os.path.isdir(input_path):
        output_dir = input_path
        csv_path = os.path.join(output_dir, "attack_scenario_summary.csv")
    else:
        csv_path = input_path
        output_dir = os.path.dirname(csv_path)

    if not os.path.exists(csv_path):
        print(f"ERROR: attack_scenario_summary.csv not found: {csv_path}")
        sys.exit(1)

    rows = read_rows(csv_path)
    plot_dir = ensure_plot_dir(output_dir)

    base_rows = [
        r
        for r in rows
        if aggregation_is_param(r)
        and routing_name(r) == "ALL"
        and scenario_name(r) in ("無防御", "no_defense", "B: 検知のみ", "b_detection_only")
    ]

    mrs, acs, succ_mat, delay_mat = build_heatmap_matrices(base_rows)
    if mrs and acs:
        plot_heatmap(
            succ_mat,
            acs,
            mrs,
            "Success Rate Heatmap",
            "Success rate",
            ".3f",
            os.path.join(plot_dir, "attack_param_success_rate_heatmap.png"),
        )
        plot_heatmap(
            delay_mat,
            acs,
            mrs,
            "Average Delay Heatmap",
            "Avg payment time",
            ".0f",
            os.path.join(plot_dir, "attack_param_delay_heatmap.png"),
        )
        plot_lines_by_mr(
            base_rows,
            success_rate,
            "Success Rate vs Attack Success",
            "Success rate",
            os.path.join(plot_dir, "attack_param_success_rate_lines.png"),
        )
        plot_lines_by_mr(
            base_rows,
            avg_delay,
            "Delay vs Attack Success",
            "Avg payment time",
            os.path.join(plot_dir, "attack_param_delay_lines.png"),
        )

    generate_defense_comparison(rows, plot_dir)
    print(f"Wrote plots under: {plot_dir}")


if __name__ == "__main__":
    main()
