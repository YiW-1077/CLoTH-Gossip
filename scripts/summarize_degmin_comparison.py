#!/usr/bin/env python3
"""次数ヒンジ D (CLOTH_SETTLE_DEGREE_MIN) の比較: deg020(D無し) / D=300 / D=150 / D=100。

比較は ratio=0.15 の行だけに揃える (D=100/150 の追試を ratio 0.15 で回したため)。
recall は分子/分母を合計してプール、FP は実数で出す。
Usage: python3 scripts/summarize_degmin_comparison.py
"""
import csv
import os

RATIO = "0.15"
# (攻撃モデル, seed, n帯, パス) — 複数 arm が同じファイルに入っていてよい
SOURCES = [
    ("lognormal", 42, "1600/6400", "/tmp/hop_grid/results_hop.csv"),
    ("lognormal", 42, "1600/6400", "/tmp/hinge_grid/results_hop.csv"),
    ("lognormal", 42, "1600/6400", "/tmp/d100_ln_seed42/results_hop.csv"),
    ("lognormal", 7,  "1600/6400", "/tmp/ver_ln_seed7/results_hop.csv"),
    ("lognormal", 7,  "1600/6400", "/tmp/d100_ln_seed7/results_hop.csv"),
    ("lognormal", 123, "1600/6400", "/tmp/ver_ln_seed123/results_hop.csv"),
    ("lognormal", 123, "1600/6400", "/tmp/d100_ln_seed123/results_hop.csv"),
    ("lognormal", 42, "12800", "/tmp/hop_grid_n12800/results_hop.csv"),
    ("lognormal", 42, "12800", "/tmp/hinge_grid_n12800/results_hop.csv"),
    ("lognormal", 42, "12800", "/tmp/d100_ln12800_seed42/results_hop.csv"),
    ("lognormal", 7,  "12800", "/tmp/ver_ln12800_seed7/results_hop.csv"),
    ("lognormal", 7,  "12800", "/tmp/d100_ln12800_seed7/results_hop.csv"),
    ("lognormal", 123, "12800", "/tmp/ver_ln12800_seed123/results_hop.csv"),
    ("lognormal", 123, "12800", "/tmp/d100_ln12800_seed123/results_hop.csv"),
    ("fixed", 42, "12800", "/tmp/ver_fx12800_seed42/results_hop.csv"),
    ("fixed", 42, "12800", "/tmp/d100_fx12800_seed42/results_hop.csv"),
]
ARMS = ["deg020", "hinge300", "hinge150", "hinge100"]
LABEL = {"deg020": "D無し(旧)", "hinge300": "D=300(現既定)", "hinge150": "D=150", "hinge100": "D=100"}


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def main():
    b = {}
    for model, seed, ngrp, path in SOURCES:
        if not os.path.exists(path):
            print(f"[warn] 未生成: {path}")
            continue
        for r in csv.DictReader(open(path)):
            if r["arm"] not in ARMS or r["malicious_ratio"] != RATIO:
                continue
            d = b.setdefault((model, seed, ngrp, r["arm"]), [0.0, 0.0, 0.0, 0.0])
            d[0] += num(r["detected_attackers"])
            d[1] += num(r["observable_attacked"])
            d[2] += num(r["false_positives"])
            d[3] += num(r["total_flagged"])

    keys = sorted({(m, s, g) for (m, s, g, _) in b}, key=lambda t: (t[0], t[2], t[1]))
    print(f"攻撃モデル=lognormal/fixed, ratio={RATIO} のみ。recall は分子/分母の合計。\n")
    print(f"{'モデル':<10s}{'seed':>5s}{'n':>11s}{'設定':>15s}{'検出/観測':>13s}"
          f"{'recall%':>9s}{'FP':>5s}{'precision%':>12s}{'Δrecall':>10s}{'ΔFP':>6s}")
    totals = {a: [0.0, 0.0, 0.0] for a in ARMS}
    for (m, s, g) in keys:
        base = b.get((m, s, g, "deg020"))
        for arm in ARMS:
            d = b.get((m, s, g, arm))
            if d is None:
                continue
            det, obs, fp, flg = d
            rec = det / obs * 100 if obs else 0.0
            prec = det / flg * 100 if flg else 0.0
            if arm == "deg020" or base is None:
                dr, dfp = "(基準)", ""
            else:
                brec = base[0] / base[1] * 100 if base[1] else 0.0
                dr, dfp = f"{rec - brec:+.1f}pp", f"{int(fp - base[2]):+d}"
            totals[arm][0] += det
            totals[arm][1] += obs
            totals[arm][2] += fp
            print(f"{m:<10s}{s:>5d}{g:>11s}{LABEL[arm]:>15s}{int(det):>7d}/{int(obs):<5d}"
                  f"{rec:>9.1f}{int(fp):>5d}{prec:>12.2f}{dr:>10s}{dfp:>6s}")
        print()

    print("=== 全セル合計 (全モデル・全seed・全n) ===")
    print(f"{'設定':>15s}{'検出/観測':>13s}{'recall%':>9s}{'FP合計':>8s}")
    for arm in ARMS:
        det, obs, fp = totals[arm]
        if obs:
            print(f"{LABEL[arm]:>15s}{int(det):>7d}/{int(obs):<5d}{det / obs * 100:>9.1f}{int(fp):>8d}")


if __name__ == "__main__":
    main()
