#!/bin/bash
# =============================================================================
# クイックテスト: run_monitor_sweep.sh と同じ条件で、1 セルだけを 3 方式 (防御なし / method1 / method2) で回し、
# 結果を 1 つの表にする。
#
# sweep の一時コピーを作り、軸のうち 取引数・金額・有意水準 の 3 行だけを書き換えて回す。
# 攻撃・検知・代役ハブ・PRT/RBR などの条件は sweep の設定ブロックそのままなので、sweep とずれない
# (設定ブロックを変えると、クイックテストも自動でその条件になる)。
# 結果はローカルの /tmp/cloth_quick_test/ に置く (NAS には送らない。走らせるたびに消して作り直す)。
# 並列は 3 本。ほかのシミュと合わせて 12 本以内に収めること。
#
# Usage: ./run_quick_test.sh [seed (既定 7)] [取引数 n (既定 400)]
#   攻撃の遅れも sweep の設定ブロックに従う (今は range = 100 ms〜10 s の一様乱数)。
#   sweep を一律 (ATTACK_DELAY_DIST=fixed) にしたときは、既定 (seed 7・n=400・金額 100・p=0.001) が
#   再ベースライン (data_rebaseline_20261013_201) の同じセルと全列一致する。range では一致しない。
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
SEED="${1:-7}"
N="${2:-400}"
AMOUNT=100
PVALUE=0.001
OUT=/tmp/cloth_quick_test

[[ "$SEED" =~ ^[0-9]+$ ]] || { echo "ERROR: seed は 0 以上の整数: $SEED"; exit 1; }
[[ "$N" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: 取引数は正の整数: $N"; exit 1; }

# sweep は自分の置き場所をプロジェクトの場所とみなすので、一時コピーはプロジェクト直下に置く (.gitignore 済み)
tmp="$PROJECT_ROOT/_quick_test_sweep.$$.sh"
trap 'rm -f "$tmp"' EXIT INT TERM
sed -e "s/^N_PAYMENTS=(.*/N_PAYMENTS=($N)/" \
    -e "s/^PAYMENT_AMOUNTS=(.*/PAYMENT_AMOUNTS=($AMOUNT)/" \
    -e "s/^P_VALUES=(.*/P_VALUES=($PVALUE)/" \
    "$PROJECT_ROOT/run_monitor_sweep.sh" > "$tmp"
chmod +x "$tmp"
# 書き換えた 3 行がそれぞれ 1 行ずつあることを確かめる (sweep の書式が変わったら止まる)
for line in "N_PAYMENTS=($N)" "PAYMENT_AMOUNTS=($AMOUNT)" "P_VALUES=($PVALUE)"; do
  if [ "$(grep -cx "$line" "$tmp")" != "1" ]; then
    echo "ERROR: sweep の軸の行を書き換えられない: $line (run_monitor_sweep.sh の設定ブロックの書式を確認すること)"
    exit 1
  fi
done

rm -rf "$OUT"
mkdir -p "$OUT"
log="$OUT/sweep.log"
echo "クイックテスト: seed=$SEED n=$N 金額=$AMOUNT sat p=$PVALUE (sweep と同じ条件・3 方式)。ログ: $log"
start=$(date +%s)
if ! "$tmp" "$SEED" "$OUT" local > "$log" 2>&1; then
  echo "ERROR: sweep が失敗した。ログの末尾:"; tail -20 "$log" | tr '\r' '\n' | tail -20
  exit 1
fi
csv=$(ls "$OUT"/*/results_summary.csv 2>/dev/null | tail -1)
if [ -z "$csv" ] || grep -q 'N/A' "$csv"; then
  echo "ERROR: results_summary.csv が無いか、N/A を含む。ログの末尾:"; tail -20 "$log" | tr '\r' '\n' | tail -20
  exit 1
fi

echo ""
# results_summary.csv を列の名前で読み、方式ごとに 1 行の表にする (全角の幅を数えて列を揃える)
python3 - "$csv" <<'PY'
import csv, sys, unicodedata

def width(s):
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in s)

def pad(s, n, right):
    sp = " " * (n - width(s))
    return sp + s if right else s + sp

rows = []
for r in csv.DictReader(open(sys.argv[1])):
    m = r["judge_method"]
    det, pr = int(r["detected_attackers"]), float(r["detection_precision_pct"])
    # 誤検知は precision から逆算する (検出 0 のときは precision が 0.00 になるので「-」と出す)
    fp = str(round(det / (pr / 100) - det)) if det > 0 and 0 < pr < 100 else ("0" if det > 0 else "-")
    nodef = m == "disable"
    rows.append(["防御なし" if nodef else m,
                 f"{float(r['grief_delay_total_ms']) / 1000:.1f}",
                 "-" if nodef else f"{float(r['grief_delay_change_vs_nodef_pct']):+.1f}%",
                 "-" if nodef else f"{det} / {r['observable_attacked']}",
                 "-" if nodef else fp,
                 f"{float(r['success_rate_pct']):.2f}%",
                 f"{float(r['avg_delay_ms']):.1f}"])
head = ["方式", "累積遅延[s]", "変化", "検出/攻撃者", "誤検知", "成功率", "平均遅延[ms]"]
ws = [max(width(x) for x in col) for col in zip(head, *rows)]
for row in [head] + rows:
    print("  ".join(pad(x, ws[j], j > 0) for j, x in enumerate(row)))
PY
echo ""
echo "変化 = 防御なしとの累積グリーフィング遅延の比較。代役ハブ (what-if) は method1・method2 にだけ入る (sweep と同じ)。"
echo "結果: $(dirname "$csv")  ($(( $(date +%s) - start )) 秒)"
