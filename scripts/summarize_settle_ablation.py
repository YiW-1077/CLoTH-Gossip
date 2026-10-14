#!/usr/bin/env python3
"""hold 検定の学習3ノブ (打ち切り学習 RL / 共通の事前分布 P / 標本ごとの標準化 S) の ablation 集計 (2026-10-13)。

どのノブが FP (正直なノードの報告) を増やしたかを、n=12800・p=0.01・3金額・3シードで比べる。
  全OFF 0/0/0 = 10/11 正式版 (repro_out_fig/data_rebaseline_20261011, CSV だけ)
  全ON  2/1/1 = 10/13 再ベースライン (NAS の rebaseline_20261013)
  1つ外す 0/1/1, 2/0/1, 2/1/0 と RL だけ 2/0/0 = NAS の ablation2_20261013/{noRL,noP,noS,RLonly}
FP(公式) = シミュの precision と同じ定義 (cloth.c: 報告あり or 評判<0.5、ただし報告の割合 < RATE_GATE_TAU の
報告由来は外す)。CSV の detected_attackers と precision から逆算する。
報告あり = 正直なノードで malicious_reports>0 (reputation_dynamics.csv、レートゲート前)。こちらは次数≤150
(ヒンジ D 以下=σ膨張なし) と大ハブに分け、10/13 の報告ありノードと同じノードかも出す。
レートゲートは通過数 (exposure) が要り、reputation_dynamics.csv からは再現できないので、ノード単位の内訳はゲート前の数。
ablation の results_summary.csv は NAS 上で作り直したものを読む
(_abl_<cfg>.sh --regen-summary <NAS の timestamp dir>)。
Usage: python3 scripts/summarize_settle_ablation.py
"""
import csv, glob, os, collections, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # scripts/nas_path.py
from nas_path import NAS_HINT, find_nas

R = find_nas()
if R is None:
    sys.exit(NAS_HINT)
LOCAL_FIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'repro_out_fig')
SEEDS = ['7', '42', '123']; AMTS = ['100', '500', '1000']
LEAF = 'avoid_low_reputation/judge_method2/n_payment12800/avg_pmt_amt={a}/judge_count=10/p_0_01'


def seed_of(ts):  # leaf の cloth_input.txt 末尾の seed= で決める (並び順に頼らない)
    for f in glob.glob(f'{ts}/{LEAF.format(a="*")}/cloth_input.txt'):
        for line in open(f):
            if line.startswith('seed='):
                return line.strip().split('=')[1]


def seed_dirs_abl(cfg):
    ts = [d for d in glob.glob(f'{R}/ablation2_20261013/{cfg}/2026*') if os.path.isdir(d)]
    m = {seed_of(d): d for d in ts}
    return m if set(m) == set(SEEDS) else {}


def seed_dirs_rb():
    return {s: glob.glob(f'{R}/rebaseline_20261013/seed{s}/2026*')[0] for s in SEEDS}


def summ(d, a):
    f = f'{d}/results_summary.csv'
    if not os.path.exists(f):
        return None
    for r in csv.DictReader(open(f)):
        if r['judge_method'] == 'method2' and r['payment_amount_sat'] == a and r['p_value'] == '0.01' \
                and r['n_transactions'] == '12800':
            return r


def nodes(d, a):
    f = f'{d}/{LEAF.format(a=a)}/reputation_dynamics.csv'
    if not os.path.exists(f):
        return None
    fp = {}; tp = 0
    for r in csv.DictReader(open(f)):
        if int(r['malicious_reports']) > 0:
            if r['is_malicious'] == '1':
                tp += 1
            else:
                fp[r['node_id']] = (int(r['degree']), float(r['reputation_score']), int(r['settle_test_count']))
    return tp, fp


def fpcount(r):
    tp = int(r['detected_attackers']); pr = float(r['detection_precision_pct'])
    return 0 if tp == 0 or pr == 0 else round(tp * 100 / pr - tp)


# no_defense の grief (10/13 = 10/11 で全セル一致) と 10/11 の method2 (全OFF)
nd = {}; off = {}
for s in SEEDS:
    for r in csv.DictReader(open(f'{LOCAL_FIG}/data_rebaseline_20261011/seed{s}/results_summary.csv')):
        if r['n_transactions'] == '12800' and r['p_value'] == '0.01':
            if r['judge_method'] == 'disable':
                nd[(s, r['payment_amount_sat'])] = float(r['grief_delay_total_ms'])
            elif r['judge_method'] == 'method2':
                off[(s, r['payment_amount_sat'])] = r
ndsum = sum(nd.values()) / 1000

print(f'NAS: {R}')
print(f"{'構成 RL/P/S':<18}{'FP公式':>6}{'報告あり':>8}{'次数≤150':>9}{'次数>150':>9}{'10/13と同じノード':>16}{'recall':>12}"
      f"{'grief計[s]':>11}{'grief削減':>9}  FP(amt100/500/1000)")
o_fp = sum(fpcount(off[(s, a)]) for s in SEEDS for a in AMTS)
o_tp = sum(int(off[(s, a)]['detected_attackers']) for s in SEEDS for a in AMTS)
o_ob = sum(int(off[(s, a)]['observable_attacked']) for s in SEEDS for a in AMTS)
o_g = sum(float(off[(s, a)]['grief_delay_total_ms']) for s in SEEDS for a in AMTS) / 1000
print(f"{'全OFF 0/0/0 (10/11)':<18}{o_fp:>6}{'-':>8}{'-':>9}{'-':>9}{'-':>16}{f'{o_tp}/{o_ob}':>12}{o_g:>11.1f}"
      f"{100 * (o_g / ndsum - 1):>8.1f}%  {[sum(fpcount(off[(s, a)]) for s in SEEDS) for a in AMTS]}")

rb = seed_dirs_rb()
ref_fp = {(s, a): nodes(rb[s], a)[1] for s in SEEDS for a in AMTS}
cfgs = [('noRL', '0/1/1 (RLを外す)'), ('noP', '2/0/1 (Pを外す)'), ('noS', '2/1/0 (Sを外す)'),
        ('RLonly', '2/0/0 (RLだけ)'), ('ALL', '2/1/1 (10/13)')]
for cfg, lab in cfgs:
    sd = rb if cfg == 'ALL' else seed_dirs_abl(cfg)
    if not sd:
        print(f'{lab:<18} 未完 (NAS に3シード揃っていない)'); continue
    F = lo = hi = ov = tp = ob = FO = 0; g = 0; per = collections.Counter(); missing = 0
    for s in SEEDS:
        for a in AMTS:
            x = nodes(sd[s], a); r = summ(sd[s], a)
            if x is None or r is None:
                missing += 1; continue
            t, fp = x; F += len(fp); per[a] += len(fp)
            lo += sum(1 for v in fp.values() if v[0] <= 150); hi += sum(1 for v in fp.values() if v[0] > 150)
            ov += len(set(fp) & set(ref_fp[(s, a)]))
            tp += int(r['detected_attackers']); ob += int(r['observable_attacked'])
            g += float(r['grief_delay_total_ms']) / 1000
            FO += fpcount(r)
    print(f"{lab:<18}{FO:>6}{F:>8}{lo:>9}{hi:>9}{f'{ov}/{F}':>16}{f'{tp}/{ob}':>12}{g:>11.1f}"
          f"{100 * (g / ndsum - 1):>8.1f}%  {[per[a] for a in AMTS]}"
          + (f'  欠け{missing} (results_summary.csv の作り直し忘れ?)' if missing else ''))
