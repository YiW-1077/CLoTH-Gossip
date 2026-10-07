#!/usr/bin/env python3
"""偽報告耐性グリッド (run_false_report_grid.sh) の集計。

見るべき指標:
  冤罪(FP)        : 正直ノードが悪意と判定された数。偽報告の直接的な被害。
  検出/観測攻撃者  : 本物の攻撃者を取りこぼしていないか(自己免罪されていないか)。
  不一致(dispute) : 相互証明の突き合わせで食い違ったリンクへの関与回数。
                     悪意ノードに偏れば「嘘の痕跡」として二次検知に使える。
Usage: python3 scripts/summarize_false_report.py [grid_dir]
"""
import csv
import os
import sys

CELLS = [
    ("cur_lie0", "現行", 0, 0), ("att_lie0", "相互証明", 0, 0),
    ("cur_lie50", "現行", 50, 0), ("att_lie50", "相互証明", 50, 0),
    ("cur_lie100", "現行", 100, 0), ("att_lie100", "相互証明", 100, 0),
    ("cur_lie200", "現行", 200, 0), ("att_lie200", "相互証明", 200, 0),
    ("att_lie100_sk10", "相互証明", 100, 10),
    ("att_lie100_sk25", "相互証明", 100, 25),
    ("att_lie100_sk50", "相互証明", 100, 50),
    ("att_lie100_sk100", "相互証明", 100, 100),
    ("cur_lie100_sk50", "現行", 100, 50),
]


def summary(d):
    out = {}
    p = os.path.join(d, "summary.csv")
    if not os.path.exists(p):
        return None
    for r in csv.reader(open(p)):
        if len(r) == 2:
            out[r[0]] = r[1]
    return out


def disputes(d):
    """悪意ノード/正直ノードごとの不一致関与回数を集計。"""
    p = os.path.join(d, "reputation_dynamics.csv")
    if not os.path.exists(p):
        return None
    mal = hon = 0
    mal_n = hon_n = 0
    for r in csv.DictReader(open(p)):
        v = float(r.get("attest_disputes", 0) or 0)
        if r["is_malicious"] == "1":
            mal += v; mal_n += 1 if v > 0 else 0
        else:
            hon += v; hon_n += 1 if v > 0 else 0
    return mal, mal_n, hon, hon_n


def main():
    g = sys.argv[1] if len(sys.argv) > 1 else "/tmp/fr_grid"
    print("偽報告(自分の申告を水増し)に対する耐性   [seed42 / lognormal / n=6400 / ratio0.15]\n")
    print(f"{'帰属方式':<10s}{'嘘[ms]':>8s}{'時計ずれ':>9s}"
          f"{'冤罪FP':>8s}{'検出/観測':>12s}{'recall%':>9s}{'precision%':>12s}"
          f"{'不一致(悪意)':>14s}{'不一致(正直)':>14s}")
    for lbl, mode, lie, sk in CELLS:
        d = os.path.join(g, lbl)
        s = summary(d)
        if s is None:
            print(f"{mode:<10s}{lie:>8d}{sk:>9d}  (未生成)")
            continue
        det = int(float(s["detected_malicious_nodes"]))
        obs = int(float(s["observable_attacked_malicious_nodes"]))
        fp = int(float(s["false_positive_nodes"]))
        rec = det / obs * 100 if obs else 0.0
        prec = float(s["malicious_detection_precision_percent"])
        dp = disputes(d)
        dmal = f"{int(dp[0])}件/{dp[1]}node" if dp else "-"
        dhon = f"{int(dp[2])}件/{dp[3]}node" if dp else "-"
        print(f"{mode:<10s}{lie:>8d}{sk:>9d}{fp:>8d}{det:>7d}/{obs:<4d}"
              f"{rec:>9.1f}{prec:>12.2f}{dmal:>14s}{dhon:>14s}")


if __name__ == "__main__":
    main()
