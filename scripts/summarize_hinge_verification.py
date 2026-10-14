#!/usr/bin/env python3
"""hinge300 (次数膨張ヒンジ化) vs deg020 (現行既定) の多シード検証を集計する。

run_hop_threshold_grid.sh が吐く results_hop.csv を複数ディレクトリから読み、
(攻撃モデル, seed, n帯) ごとに arm を比較する。recall は分子/分母を合計してプールし、
FP は実数で出す (0/1/2 の小標本なので % にしない)。
Usage: python3 scripts/summarize_hinge_verification.py
"""
import csv
import glob
import os
import sys

SUB = "thesis/2026bachelor-af23/AF23027王毅恒"
# 二重マウントで /Volumes/public1-1 等になることがあるので、置き場所が見えるものを使う
NAS = next((f"{m}/{SUB}" for m in sorted(glob.glob("/Volumes/public1*")) if os.path.isdir(f"{m}/{SUB}")), None)
if NAS is None:
    sys.exit("NAS が見えない: open smb://morinolab@172.20.86.110/public1 でマウントする")

# (ラベル, 攻撃モデル, seed, n帯, results_hop.csv の NAS からの相対パス)
# run_hop_threshold_grid.sh <out_dir> の結果は NAS の <out_dir の名前>/ に置かれる。
# ここに並べた 2026-10-06 の run は /tmp に出していて再起動で消えた (NAS にも無い) ので、今は全部「見つかりません」になる。
SOURCES = [
    ("lognormal", 42,  "1600/6400", "hop_grid/results_hop.csv"),
    ("lognormal", 42,  "1600/6400", "hinge_grid/results_hop.csv"),
    ("lognormal", 42,  "12800",     "hop_grid_n12800/results_hop.csv"),
    ("lognormal", 42,  "12800",     "hinge_grid_n12800/results_hop.csv"),
    ("lognormal", 7,   "1600/6400", "ver_ln_seed7/results_hop.csv"),
    ("lognormal", 123, "1600/6400", "ver_ln_seed123/results_hop.csv"),
    ("lognormal", 7,   "12800",     "ver_ln12800_seed7/results_hop.csv"),
    ("lognormal", 123, "12800",     "ver_ln12800_seed123/results_hop.csv"),
    ("fixed",     42,  "6400",      "ver_fx_seed42/results_hop.csv"),
    ("fixed",     7,   "6400",      "ver_fx_seed7/results_hop.csv"),
    ("fixed",     123, "6400",      "ver_fx_seed123/results_hop.csv"),
    ("fixed",     42,  "12800",     "ver_fx12800_seed42/results_hop.csv"),
]
ARMS = ["deg020", "hinge300"]


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def main():
    buckets = {}
    for model, seed, ngrp, path in SOURCES:
        path = os.path.join(NAS, path)
        if not os.path.exists(path):
            print(f"[warn] 見つかりません: {path}")
            continue
        for r in csv.DictReader(open(path)):
            if r["arm"] not in ARMS:
                continue
            k = (model, seed, ngrp, r["arm"])
            d = buckets.setdefault(k, [0.0, 0.0, 0.0, 0.0])
            d[0] += num(r["detected_attackers"])
            d[1] += num(r["observable_attacked"])
            d[2] += num(r["false_positives"])
            d[3] += num(r["total_flagged"])

    keys = sorted({(m, s, g) for (m, s, g, _) in buckets}, key=lambda t: (t[0], t[2], t[1]))
    print(f"{'攻撃モデル':<11s}{'seed':>5s}{'n':>11s}{'arm':>10s}{'検出/観測':>14s}"
          f"{'recall%':>9s}{'FP':>5s}{'precision%':>12s}{'Δrecall':>10s}{'ΔFP':>6s}")
    wins = {"recall": 0, "fp_better": 0, "fp_worse": 0, "cells": 0}
    for (m, s, g) in keys:
        base = buckets.get((m, s, g, "deg020"))
        for arm in ARMS:
            d = buckets.get((m, s, g, arm))
            if d is None:
                continue
            det, obs, fp, flg = d
            rec = det / obs * 100 if obs else 0.0
            prec = det / flg * 100 if flg else 0.0
            if arm == "deg020" or base is None:
                dr, dfp = "(基準)", ""
            else:
                brec = base[0] / base[1] * 100 if base[1] else 0.0
                dr = f"{rec - brec:+.1f}pp"
                dfp = f"{int(fp - base[2]):+d}"
                wins["cells"] += 1
                if rec > brec:
                    wins["recall"] += 1
                if fp < base[2]:
                    wins["fp_better"] += 1
                if fp > base[2]:
                    wins["fp_worse"] += 1
            print(f"{m:<11s}{s:>5d}{g:>11s}{arm:>10s}{int(det):>8d}/{int(obs):<5d}"
                  f"{rec:>9.1f}{int(fp):>5d}{prec:>12.2f}{dr:>10s}{dfp:>6s}")
        print()

    print(f"=== hinge300 の対現行成績: {wins['cells']} 比較中 "
          f"recall 改善 {wins['recall']} / FP 改善 {wins['fp_better']} / FP 悪化 {wins['fp_worse']} ===")


if __name__ == "__main__":
    main()
