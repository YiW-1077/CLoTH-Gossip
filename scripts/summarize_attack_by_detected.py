"""
攻撃検出の有無で支払いを分類し、それぞれのメトリクスを比較するスクリプト。

支払いを以下の3カテゴリに分類：
  1. 攻撃なし (no_attack): is_attacked = False
  2. 攻撃検出 (detected): is_attacked = True
  3. 全体 (all): 全支払い

各カテゴリについて成功率、失敗理由分布、平均手数料などを集計する。
"""

import csv
import os
import statistics
import sys
from collections import defaultdict

csv.field_size_limit(sys.maxsize)


SCENARIO_ALIASES = {
    "a_no_attack": "a_no_attack",
    "baseline_no_attack": "a_no_attack",
    "b_detection_only": "b_detection_only",
    "detection_only": "b_detection_only",
    "c_full_defense": "c_full_defense",
    "full_defense": "c_full_defense",
    "d_extreme_no_defense": "d_extreme_no_defense",
    "e_extreme_full_defense": "e_extreme_full_defense",
    "no_defense": "no_defense",
}

SCENARIO_ORDER = [
    "a_no_attack",
    "b_detection_only",
    "c_full_defense",
    "no_defense",
    "d_extreme_no_defense",
    "e_extreme_full_defense",
]

SCENARIO_LABELS_JA = {
    "a_no_attack": "A: 攻撃なし",
    "b_detection_only": "B: 検知のみ",
    "c_full_defense": "C: フル防御",
    "no_defense": "無防御",
    "d_extreme_no_defense": "D: 極端攻撃・無防御",
    "e_extreme_full_defense": "E: 極端攻撃・フル防御",
}

ATTACK_DETECTION_LABELS_JA = {
    "all": "全体",
    "no_attack": "攻撃なし",
    "detected": "攻撃検出",
}


def to_float(value):
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (ValueError, TypeError):
        return None


def to_bool_num(value):
    if value is None:
        return None
    s = str(value).strip().lower()
    if s == "true":
        return 1.0
    if s == "false":
        return 0.0
    return None


def avg(values):
    filtered = [v for v in values if v is not None]
    if not filtered:
        return ""
    return statistics.mean(filtered)


def extract_scenario(text):
    wrapped = "/" + str(text).strip("/") + "/"
    for alias, canonical in SCENARIO_ALIASES.items():
        if f"/{alias}/" in wrapped:
            return canonical
    return None


def extract_routing_method(text):
    wrapped = "/" + str(text).strip("/") + "/"
    marker = "/routing_method="
    pos = wrapped.find(marker)
    if pos < 0:
        return ""
    tail = wrapped[pos + len(marker) :]
    return tail.split("/", 1)[0]


def route_hops(route):
    s = (route or "").strip()
    if not s:
        return None
    nodes = [x for x in s.split("-") if x != ""]
    if len(nodes) <= 1:
        return 0
    return len(nodes) - 1


def parse_run_metrics_by_attack(run_dir):
    """
    payments_output.csv から攻撃検出有無で分類したメトリクスを計算
    
    Returns: dict with keys "all", "no_attack", "detected"
            Each value is a dict with metrics
    """
    payments_csv = os.path.join(run_dir, "payments_output.csv")
    if not os.path.exists(payments_csv):
        return None

    # 各分類のメトリクス
    categories = {
        "all": {
            "n": 0,
            "succ": 0,
            "sum_time": 0.0,
            "sum_fee": 0.0,
            "sum_attempts": 0.0,
            "no_balance_hits": 0,
            "offline_hits": 0,
            "timeout_hits": 0,
            "no_path_hits": 0,
            "hops_sum": 0,
            "hops_n": 0,
        },
        "no_attack": {
            "n": 0,
            "succ": 0,
            "sum_time": 0.0,
            "sum_fee": 0.0,
            "sum_attempts": 0.0,
            "no_balance_hits": 0,
            "offline_hits": 0,
            "timeout_hits": 0,
            "no_path_hits": 0,
            "hops_sum": 0,
            "hops_n": 0,
        },
        "detected": {
            "n": 0,
            "succ": 0,
            "sum_time": 0.0,
            "sum_fee": 0.0,
            "sum_attempts": 0.0,
            "no_balance_hits": 0,
            "offline_hits": 0,
            "timeout_hits": 0,
            "no_path_hits": 0,
            "hops_sum": 0,
            "hops_n": 0,
        },
    }

    with open(payments_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            is_success = str(row.get("is_success", "")).strip() == "1"
            
            # 攻撃判定
            attack_delay = to_float(row.get("attack_delay_total")) or 0.0
            attack_events = to_float(row.get("attack_delay_events")) or 0.0
            is_attacked = attack_delay > 0.0 or attack_events > 0.0
            
            # どのカテゴリに属するか
            cat_key = "detected" if is_attacked else "no_attack"
            
            for cat in ["all", cat_key]:
                categories[cat]["n"] += 1
                
                if is_success:
                    categories[cat]["succ"] += 1
                
                start = to_float(row.get("start_time"))
                end = to_float(row.get("end_time"))
                if start is not None and end is not None:
                    categories[cat]["sum_time"] += end - start
                
                categories[cat]["sum_fee"] += to_float(row.get("total_fee")) or 0.0
                categories[cat]["sum_attempts"] += to_float(row.get("attempts")) or 0.0
                
                if (to_float(row.get("no_balance_count")) or 0.0) > 0:
                    categories[cat]["no_balance_hits"] += 1
                if (to_float(row.get("offline_node_count")) or 0.0) > 0:
                    categories[cat]["offline_hits"] += 1
                if (to_float(row.get("timeout_exp")) or 0.0) > 0:
                    categories[cat]["timeout_hits"] += 1
                if (to_float(row.get("no_path_exp")) or 0.0) > 0:
                    categories[cat]["no_path_hits"] += 1
                
                if is_success:
                    hops = route_hops(row.get("route"))
                    if hops is not None:
                        categories[cat]["hops_sum"] += hops
                        categories[cat]["hops_n"] += 1
    
    return categories


def process_simulations(summary_csv_path, output_dir):
    """
    summary.csv を読んで各シミュレーション対象を処理
    """
    
    # 攻撃検出有無で分類した集計結果
    # key: (routing_method, scenario, attack_detection_type)
    aggregated = defaultdict(lambda: {
        "run_results": [],  # 各ランの結果
    })
    
    if not os.path.exists(summary_csv_path):
        print(f"Error: {summary_csv_path} not found")
        return
    
    with open(summary_csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            run_dir = row.get("run_dir", "").strip()
            if not run_dir or not os.path.isdir(run_dir):
                continue
            
            scenario = extract_scenario(run_dir)
            routing_method = extract_routing_method(run_dir)
            
            if not scenario:
                continue
            
            metrics = parse_run_metrics_by_attack(run_dir)
            if not metrics:
                continue
            
            # 各攻撃検出カテゴリについて集計
            for attack_key in ["all", "no_attack", "detected"]:
                agg_key = (routing_method, scenario, attack_key)
                aggregated[agg_key]["run_results"].append(metrics[attack_key])
    
    # CSV出力
    output_csv = os.path.join(output_dir, "attack_detection_summary.csv")
    
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        # ヘッダ
        headers = [
            "ルーティング方式",
            "シナリオ",
            "攻撃検出分類",
            "件数",
            "成功率(平均)",
            "失敗率_経路なし(平均)",
            "失敗率_代替経路なし(平均)",
            "失敗率_タイムアウト(平均)",
            "再試行率(平均)",
            "再試行率_残高不足(平均)",
            "所要時間平均",
            "手数料平均",
            "成功時平均ホップ数",
            "実データ_ラン数",
        ]
        writer.writerow(headers)
        
        # データ行
        for agg_key in sorted(aggregated.keys()):
            routing_method, scenario, attack_key = agg_key
            run_results = aggregated[agg_key]["run_results"]
            
            if not run_results:
                continue
            
            # 各メトリクスを計算
            scenario_label = SCENARIO_LABELS_JA.get(scenario, scenario)
            attack_label = ATTACK_DETECTION_LABELS_JA.get(attack_key, attack_key)
            
            # 集計
            n_runs = len(run_results)
            
            # 件数（複数ランの平均）
            n_list = [r["n"] for r in run_results]
            n_avg = avg(n_list) if n_list else ""
            
            # 成功率
            success_rates = []
            for r in run_results:
                if r["n"] > 0:
                    success_rates.append(r["succ"] / r["n"])
            success_rate = avg(success_rates) if success_rates else ""
            
            # 失敗理由分布
            fail_no_path_rates = []
            fail_no_alt_rates = []
            fail_timeout_rates = []
            retry_rates = []
            retry_no_balance_rates = []
            
            for r in run_results:
                if r["n"] > 0:
                    fail_n = r["n"] - r["succ"]
                    fail_no_path_rates.append(r["no_path_hits"] / r["n"])
                    # 代替経路なしは別途計算必要（ここでは0とする）
                    fail_no_alt_rates.append(0)
                    fail_timeout_rates.append(r["timeout_hits"] / r["n"])
                    retry_rates.append(r["sum_attempts"] / r["n"] - 1 if r["n"] > 0 else 0)
                    if r["sum_attempts"] > 0:
                        retry_no_balance_rates.append(r["no_balance_hits"] / r["n"])
                    else:
                        retry_no_balance_rates.append(0)
            
            fail_no_path_rate = avg(fail_no_path_rates) if fail_no_path_rates else ""
            fail_no_alt_rate = avg(fail_no_alt_rates) if fail_no_alt_rates else ""
            fail_timeout_rate = avg(fail_timeout_rates) if fail_timeout_rates else ""
            retry_rate = avg(retry_rates) if retry_rates else ""
            retry_no_balance_rate = avg(retry_no_balance_rates) if retry_no_balance_rates else ""
            
            # 平均時間・手数料
            sum_time_list = [r["sum_time"] for r in run_results]
            sum_fee_list = [r["sum_fee"] for r in run_results]
            avg_time = sum(sum_time_list) / sum(n_list) if n_list and sum(n_list) > 0 else ""
            avg_fee = sum(sum_fee_list) / sum(n_list) if n_list and sum(n_list) > 0 else ""
            
            # 成功時平均ホップ数
            hops_sums = [r["hops_sum"] for r in run_results]
            hops_ns = [r["hops_n"] for r in run_results]
            avg_hops = sum(hops_sums) / sum(hops_ns) if sum(hops_ns) > 0 else ""
            
            # パーセンテージ形式に
            def format_pct(val):
                if val == "" or val is None:
                    return ""
                return f"{val * 100:.2f}%"
            
            row = [
                routing_method,
                scenario_label,
                attack_label,
                f"{n_avg:.0f}" if n_avg != "" else "",
                format_pct(success_rate),
                format_pct(fail_no_path_rate),
                format_pct(fail_no_alt_rate),
                format_pct(fail_timeout_rate),
                format_pct(retry_rate),
                format_pct(retry_no_balance_rate),
                f"{avg_time:.2f}" if avg_time != "" else "",
                f"{avg_fee:.2f}" if avg_fee != "" else "",
                f"{avg_hops:.2f}" if avg_hops != "" else "",
                n_runs,
            ]
            
            writer.writerow(row)
    
    print(f"✓ Output written to {output_csv}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python summarize_attack_by_detected.py <summary_csv> [output_dir]")
        sys.exit(1)
    
    summary_csv_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(summary_csv_path)
    
    process_simulations(summary_csv_path, output_dir)


if __name__ == "__main__":
    main()
