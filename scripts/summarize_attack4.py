"""
attack 系シナリオの比較サマリを 1 つの CSV にまとめるスクリプト。

summary.csv 由来の従来メトリクスに加えて、各 run 配下の生データ
（payments_output.csv / edges_output.csv / nodes_output.csv）から
攻撃影響・ネットワーク影響の指標も集計して attack_scenario_summary.csv に出力する。
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

SUMMARY_METRICS = [
    "success_rate",
    "fail_no_path_rate",
    "fail_no_alternative_path_rate",
    "fail_timeout_rate",
    "retry_rate",
    "retry_no_balance_rate",
    "time/average",
    "fee/average",
    "route_len/average",
]

PARAM_METRICS = [
    "#param/malicious_node_ratio",
    "#param/malicious_failure_probability",
    "#param/enable_network_attack_delay",
    "#param/attack_delay_intensity",
    "#param/attack_delay_duration",
    "#param/attack_delay_jitter",
    "#param/attack_delay_start_time",
]

RAW_METRICS = [
    "raw/n_runs",
    "raw/n_payments/mean",
    "raw/success_rate/mean",
    "raw/avg_payment_time/mean",
    "raw/avg_total_fee/mean",
    "raw/attacked_payment_ratio/mean",
    "raw/attacked_success_rate/mean",
    "raw/nonattacked_success_rate/mean",
    "raw/avg_attempts/mean",
    "raw/no_balance_hit_rate/mean",
    "raw/offline_hit_rate/mean",
    "raw/timeout_hit_rate/mean",
    "raw/avg_route_hops_success/mean",
    "raw/edge_closed_ratio/mean",
    "raw/edge_avg_tot_flows/mean",
    "raw/edge_avg_balance/mean",
    "raw/node_avg_open_edges/mean",
]

SCENARIO_LABELS_JA = {
    "a_no_attack": "A: 攻撃なし",
    "b_detection_only": "B: 検知のみ",
    "c_full_defense": "C: フル防御",
    "no_defense": "無防御",
    "d_extreme_no_defense": "D: 極端攻撃・無防御",
    "e_extreme_full_defense": "E: 極端攻撃・フル防御",
}

AGGREGATION_LABELS_JA = {
    "scenario": "シナリオ集計",
    "scenario_by_attack_params": "シナリオ×攻撃パラメータ集計",
}

COLUMN_LABELS_JA = {
    "routing_method": "ルーティング方式",
    "scenario": "シナリオ",
    "aggregation_level": "集計レベル",
    "malicious_node_ratio": "攻撃ノード割合",
    "malicious_failure_probability": "攻撃成功確率",
    "n": "件数",
    "success_rate/mean": "成功率(平均)",
    "fail_no_path_rate/mean": "失敗率_経路なし(平均)",
    "fail_no_alternative_path_rate/mean": "失敗率_代替経路なし(平均)",
    "fail_timeout_rate/mean": "失敗率_タイムアウト(平均)",
    "retry_rate/mean": "再試行率(平均)",
    "retry_no_balance_rate/mean": "再試行率_残高不足(平均)",
    "time/average/mean": "所要時間平均(summary由来)",
    "fee/average/mean": "手数料平均(summary由来)",
    "route_len/average/mean": "経路長平均(summary由来)",
    "#param/malicious_node_ratio/mean": "設定_攻撃ノード割合(平均)",
    "#param/malicious_failure_probability/mean": "設定_攻撃成功確率(平均)",
    "#param/enable_network_attack_delay/mean": "設定_攻撃遅延有効(平均)",
    "#param/attack_delay_intensity/mean": "設定_攻撃遅延強度(平均)",
    "#param/attack_delay_duration/mean": "設定_攻撃遅延期間(平均)",
    "#param/attack_delay_jitter/mean": "設定_攻撃遅延ジッタ(平均)",
    "#param/attack_delay_start_time/mean": "設定_攻撃遅延開始時刻(平均)",
    "raw/n_runs": "実データ_ラン数",
    "raw/n_payments/mean": "実データ_支払い件数(平均)",
    "raw/success_rate/mean": "実データ_成功率(平均)",
    "raw/avg_payment_time/mean": "実データ_平均支払い時間",
    "raw/avg_total_fee/mean": "実データ_平均総手数料",
    "raw/attacked_payment_ratio/mean": "実データ_攻撃影響支払い比率",
    "raw/attacked_success_rate/mean": "実データ_攻撃影響支払い成功率",
    "raw/nonattacked_success_rate/mean": "実データ_非攻撃支払い成功率",
    "raw/avg_attempts/mean": "実データ_平均試行回数",
    "raw/no_balance_hit_rate/mean": "実データ_残高不足発生率",
    "raw/offline_hit_rate/mean": "実データ_オフライン発生率",
    "raw/timeout_hit_rate/mean": "実データ_タイムアウト発生率",
    "raw/avg_route_hops_success/mean": "実データ_成功時平均ホップ数",
    "raw/edge_closed_ratio/mean": "実データ_閉鎖エッジ比率",
    "raw/edge_avg_tot_flows/mean": "実データ_エッジ平均フロー数",
    "raw/edge_avg_balance/mean": "実データ_エッジ平均残高",
    "raw/node_avg_open_edges/mean": "実データ_ノード平均オープンエッジ数",
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


def parse_run_metrics(run_dir):
    payments_csv = os.path.join(run_dir, "payments_output.csv")
    if not os.path.exists(payments_csv):
        return None

    n = 0
    succ = 0
    sum_time = 0.0
    sum_fee = 0.0
    sum_attempts = 0.0
    attacked = 0
    attacked_success = 0
    nonattacked = 0
    nonattacked_success = 0
    no_balance_hits = 0
    offline_hits = 0
    timeout_hits = 0
    hops_sum = 0
    hops_n = 0

    with open(payments_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            n += 1
            is_success = str(row.get("is_success", "")).strip() == "1"
            if is_success:
                succ += 1

            start = to_float(row.get("start_time"))
            end = to_float(row.get("end_time"))
            if start is not None and end is not None:
                sum_time += end - start

            sum_fee += to_float(row.get("total_fee")) or 0.0
            sum_attempts += to_float(row.get("attempts")) or 0.0

            if (to_float(row.get("no_balance_count")) or 0.0) > 0:
                no_balance_hits += 1
            if (to_float(row.get("offline_node_count")) or 0.0) > 0:
                offline_hits += 1
            if (to_float(row.get("timeout_exp")) or 0.0) > 0:
                timeout_hits += 1

            attack_delay = to_float(row.get("attack_delay_total")) or 0.0
            attack_events = to_float(row.get("attack_delay_events")) or 0.0
            is_attacked = attack_delay > 0.0 or attack_events > 0.0
            if is_attacked:
                attacked += 1
                if is_success:
                    attacked_success += 1
            else:
                nonattacked += 1
                if is_success:
                    nonattacked_success += 1

            if is_success:
                hops = route_hops(row.get("route"))
                if hops is not None:
                    hops_sum += hops
                    hops_n += 1

    if n == 0:
        return None

    edge_closed_ratio = None
    edge_avg_tot_flows = None
    edge_avg_balance = None
    edges_csv = os.path.join(run_dir, "edges_output.csv")
    if os.path.exists(edges_csv):
        edge_n = 0
        edge_closed = 0
        edge_flows_sum = 0.0
        edge_balance_sum = 0.0
        with open(edges_csv, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                edge_n += 1
                if str(row.get("is_closed", "")).strip() == "1":
                    edge_closed += 1
                edge_flows_sum += to_float(row.get("tot_flows")) or 0.0
                edge_balance_sum += to_float(row.get("balance")) or 0.0
        if edge_n > 0:
            edge_closed_ratio = edge_closed / edge_n
            edge_avg_tot_flows = edge_flows_sum / edge_n
            edge_avg_balance = edge_balance_sum / edge_n

    node_avg_open_edges = None
    nodes_csv = os.path.join(run_dir, "nodes_output.csv")
    if os.path.exists(nodes_csv):
        node_n = 0
        node_open_sum = 0.0
        with open(nodes_csv, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                node_n += 1
                node_open_sum += to_float(row.get("open_edges")) or 0.0
        if node_n > 0:
            node_avg_open_edges = node_open_sum / node_n

    return {
        "raw/n_payments/mean": n,
        "raw/success_rate/mean": succ / n,
        "raw/avg_payment_time/mean": sum_time / n,
        "raw/avg_total_fee/mean": sum_fee / n,
        "raw/attacked_payment_ratio/mean": attacked / n,
        "raw/attacked_success_rate/mean": (attacked_success / attacked) if attacked > 0 else None,
        "raw/nonattacked_success_rate/mean": (nonattacked_success / nonattacked) if nonattacked > 0 else None,
        "raw/avg_attempts/mean": sum_attempts / n,
        "raw/no_balance_hit_rate/mean": no_balance_hits / n,
        "raw/offline_hit_rate/mean": offline_hits / n,
        "raw/timeout_hit_rate/mean": timeout_hits / n,
        "raw/avg_route_hops_success/mean": (hops_sum / hops_n) if hops_n > 0 else None,
        "raw/edge_closed_ratio/mean": edge_closed_ratio,
        "raw/edge_avg_tot_flows/mean": edge_avg_tot_flows,
        "raw/edge_avg_balance/mean": edge_avg_balance,
        "raw/node_avg_open_edges/mean": node_avg_open_edges,
    }


def parse_run_params(run_dir):
    cloth_input = os.path.join(run_dir, "cloth_input.txt")
    out = {}
    if not os.path.exists(cloth_input):
        return out

    with open(cloth_input, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key == "malicious_node_ratio":
                out["#param/malicious_node_ratio"] = to_float(value)
            elif key == "malicious_failure_probability":
                out["#param/malicious_failure_probability"] = to_float(value)
            elif key == "enable_network_attack_delay":
                out["#param/enable_network_attack_delay"] = to_bool_num(value)
            elif key == "attack_delay_intensity":
                out["#param/attack_delay_intensity"] = to_float(value)
            elif key == "attack_delay_duration":
                out["#param/attack_delay_duration"] = to_float(value)
            elif key == "attack_delay_jitter":
                out["#param/attack_delay_jitter"] = to_float(value)
            elif key == "attack_delay_start_time":
                out["#param/attack_delay_start_time"] = to_float(value)
    return out


def normalize_param_value(value):
    fv = to_float(value)
    if fv is None:
        return ""
    return f"{fv:g}"


def param_sort_key(value):
    if value == "":
        return (0, 0.0)
    try:
        return (1, float(value))
    except ValueError:
        return (2, value)


def ordered_scenarios(scenarios):
    preferred = [s for s in SCENARIO_ORDER if s in scenarios]
    extras = sorted([s for s in scenarios if s not in SCENARIO_ORDER])
    return preferred + extras


def localize_row(row):
    localized = {}
    for key, value in row.items():
        out_key = COLUMN_LABELS_JA.get(key, key)
        out_value = value
        if key == "scenario":
            out_value = SCENARIO_LABELS_JA.get(str(value), value)
        elif key == "aggregation_level":
            out_value = AGGREGATION_LABELS_JA.get(str(value), value)
        localized[out_key] = out_value
    return localized


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/summarize_attack4.py <output_dir_or_summary_csv>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_dir = input_path if os.path.isdir(input_path) else os.path.dirname(input_path)
    summary_csv = input_path if input_path.endswith(".csv") else os.path.join(output_dir, "summary.csv")

    by_method_scenario_summary = defaultdict(list)
    by_scenario_summary = defaultdict(list)
    by_method_scenario_param_summary = defaultdict(list)
    by_scenario_param_summary = defaultdict(list)
    by_method_scenario_raw = defaultdict(list)
    by_scenario_raw = defaultdict(list)
    by_method_scenario_param_raw = defaultdict(list)
    by_scenario_param_raw = defaultdict(list)
    methods = set()
    scenarios = set()

    if os.path.exists(summary_csv):
        with open(summary_csv, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                method = row.get("#param/routing_method", "")
                scenario = extract_scenario(row.get("simulation_id", ""))
                if method == "" or scenario is None:
                    continue
                ratio_key = normalize_param_value(row.get("#param/malicious_node_ratio"))
                prob_key = normalize_param_value(row.get("#param/malicious_failure_probability"))
                methods.add(method)
                scenarios.add(scenario)
                by_method_scenario_summary[(method, scenario)].append(row)
                by_scenario_summary[scenario].append(row)
                by_method_scenario_param_summary[(method, scenario, ratio_key, prob_key)].append(row)
                by_scenario_param_summary[(scenario, ratio_key, prob_key)].append(row)

    if os.path.isdir(output_dir):
        for root, _, files in os.walk(output_dir):
            if "payments_output.csv" not in files:
                continue
            scenario = extract_scenario(root)
            method = extract_routing_method(root)
            if scenario is None or method == "":
                continue
            run_metrics = parse_run_metrics(root)
            if run_metrics is None:
                continue
            run_metrics.update(parse_run_params(root))
            ratio_key = normalize_param_value(run_metrics.get("#param/malicious_node_ratio"))
            prob_key = normalize_param_value(run_metrics.get("#param/malicious_failure_probability"))
            methods.add(method)
            scenarios.add(scenario)
            by_method_scenario_raw[(method, scenario)].append(run_metrics)
            by_scenario_raw[scenario].append(run_metrics)
            by_method_scenario_param_raw[(method, scenario, ratio_key, prob_key)].append(run_metrics)
            by_scenario_param_raw[(scenario, ratio_key, prob_key)].append(run_metrics)

    if not methods or not scenarios:
        print(f"ERROR: no scenario data found in {input_path}")
        sys.exit(1)

    summary_path = os.path.join(output_dir, "attack_scenario_summary.csv")
    fieldnames = (
        ["routing_method", "scenario", "aggregation_level", "malicious_node_ratio", "malicious_failure_probability", "n"]
        + [f"{m}/mean" for m in SUMMARY_METRICS]
        + [f"{p}/mean" for p in PARAM_METRICS]
        + RAW_METRICS
    )
    localized_fieldnames = [COLUMN_LABELS_JA.get(c, c) for c in fieldnames]

    def build_output_row(method, scenario, aggregation_level, ratio_key, prob_key, s_rows, r_rows):
        out = {
            "routing_method": method,
            "scenario": scenario,
            "aggregation_level": aggregation_level,
            "malicious_node_ratio": ratio_key,
            "malicious_failure_probability": prob_key,
            "n": len(s_rows) if len(s_rows) > 0 else len(r_rows),
        }

        for metric in SUMMARY_METRICS:
            out[f"{metric}/mean"] = avg([to_float(r.get(metric)) for r in s_rows])

        for param in PARAM_METRICS:
            if param == "#param/enable_network_attack_delay":
                s_vals = [to_bool_num(r.get(param)) for r in s_rows]
                r_vals = [to_float(r.get(param)) for r in r_rows]
            else:
                s_vals = [to_float(r.get(param)) for r in s_rows]
                r_vals = [to_float(r.get(param)) for r in r_rows]
            param_avg = avg(s_vals)
            if param_avg == "":
                param_avg = avg(r_vals)
            out[f"{param}/mean"] = param_avg

        out["raw/n_runs"] = len(r_rows)
        for raw_metric in RAW_METRICS:
            if raw_metric == "raw/n_runs":
                continue
            out[raw_metric] = avg([to_float(r.get(raw_metric)) for r in r_rows])
        return out

    def write_summary_csv(path):
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=localized_fieldnames)
            writer.writeheader()

            scenario_list = ordered_scenarios(scenarios)
            for method in sorted(methods):
                for scenario in scenario_list:
                    s_rows = by_method_scenario_summary.get((method, scenario), [])
                    r_rows = by_method_scenario_raw.get((method, scenario), [])
                    writer.writerow(localize_row(build_output_row(method, scenario, "scenario", "", "", s_rows, r_rows)))

                    param_keys = set()
                    for k in by_method_scenario_param_summary.keys():
                        if k[0] == method and k[1] == scenario:
                            param_keys.add((k[2], k[3]))
                    for k in by_method_scenario_param_raw.keys():
                        if k[0] == method and k[1] == scenario:
                            param_keys.add((k[2], k[3]))

                    for ratio_key, prob_key in sorted(param_keys, key=lambda x: (param_sort_key(x[0]), param_sort_key(x[1]))):
                        s_rows_param = by_method_scenario_param_summary.get((method, scenario, ratio_key, prob_key), [])
                        r_rows_param = by_method_scenario_param_raw.get((method, scenario, ratio_key, prob_key), [])
                        writer.writerow(
                            localize_row(
                                build_output_row(
                                    method,
                                    scenario,
                                    "scenario_by_attack_params",
                                    ratio_key,
                                    prob_key,
                                    s_rows_param,
                                    r_rows_param,
                                )
                            )
                        )

            for scenario in scenario_list:
                s_rows = by_scenario_summary.get(scenario, [])
                r_rows = by_scenario_raw.get(scenario, [])
                writer.writerow(localize_row(build_output_row("ALL", scenario, "scenario", "", "", s_rows, r_rows)))

                param_keys = set()
                for k in by_scenario_param_summary.keys():
                    if k[0] == scenario:
                        param_keys.add((k[1], k[2]))
                for k in by_scenario_param_raw.keys():
                    if k[0] == scenario:
                        param_keys.add((k[1], k[2]))

                for ratio_key, prob_key in sorted(param_keys, key=lambda x: (param_sort_key(x[0]), param_sort_key(x[1]))):
                    s_rows_param = by_scenario_param_summary.get((scenario, ratio_key, prob_key), [])
                    r_rows_param = by_scenario_param_raw.get((scenario, ratio_key, prob_key), [])
                    writer.writerow(
                        localize_row(
                            build_output_row(
                                "ALL",
                                scenario,
                                "scenario_by_attack_params",
                                ratio_key,
                                prob_key,
                                s_rows_param,
                                r_rows_param,
                            )
                        )
                    )

    tmp_path = summary_path + ".tmp"
    write_summary_csv(tmp_path)
    os.replace(tmp_path, summary_path)
    print(f"Wrote: {summary_path}")


if __name__ == "__main__":
    main()
