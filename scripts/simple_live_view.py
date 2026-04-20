#!/usr/bin/env python3
import csv
import math
import os
import sys
import time

def wait_for_file(path, timeout_sec=60):
    start = time.time()
    while time.time() - start < timeout_sec:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return True
        time.sleep(0.2)
    return False


def load_nodes(nodes_path):
    node_ids = []
    is_malicious = {}
    is_monitor = {}
    with open(nodes_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            nid = int(row["id"])
            node_ids.append(nid)
            is_malicious[nid] = int(row["is_malicious"]) == 1
            is_monitor[nid] = int(row["is_monitor"]) == 1
    return node_ids, is_malicious, is_monitor


def load_edges(edges_path):
    edges = []
    with open(edges_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            edges.append((int(row["node1"]), int(row["node2"])))
    return edges


def build_circle_layout(node_ids):
    n = max(len(node_ids), 1)
    radius = 1.0
    coords = {}
    for i, nid in enumerate(node_ids):
        theta = (2.0 * math.pi * i) / n
        coords[nid] = (radius * math.cos(theta), radius * math.sin(theta))
    return coords


def read_state(state_path):
    try:
        with open(state_path, "r") as f:
            line = f.read().strip()
        if not line:
            return None
        vals = line.split(",")
        if len(vals) < 6:
            return None
        return {
            "completed": int(vals[0]),
            "total": int(vals[1]),
            "time": int(vals[2]),
            "payment_id": int(vals[3]),
            "event": vals[4],
            "node_id": int(vals[5]),
            "route": vals[6] if len(vals) >= 7 else "",
        }
    except (OSError, ValueError):
        return None


def parse_route_edges(route_text):
    if not route_text:
        return []
    route_edges = []
    for token in route_text.split("|"):
        parts = token.split("-")
        if len(parts) != 2:
            continue
        try:
            n1 = int(parts[0])
            n2 = int(parts[1])
        except ValueError:
            continue
        route_edges.append((n1, n2))
    return route_edges


def is_finished(progress_path):
    if not os.path.exists(progress_path):
        return False
    try:
        with open(progress_path, "r") as f:
            data = f.read().strip()
        return data == "1" or data == "failed"
    except OSError:
        return False


def main():
    try:
        import matplotlib.pyplot as plt
        from matplotlib.collections import LineCollection
    except ImportError:
        return 0

    if len(sys.argv) != 2:
        print("usage: simple_live_view.py <result_dir>")
        return 1

    result_dir = sys.argv[1]
    nodes_path = os.path.join(result_dir, "simple_view_nodes.csv")
    edges_path = os.path.join(result_dir, "simple_view_edges.csv")
    state_path = os.path.join(result_dir, "simple_view_state.tmp")
    progress_path = os.path.join(result_dir, "progress.tmp")

    if not wait_for_file(nodes_path) or not wait_for_file(edges_path):
        return 0

    node_ids, is_malicious, is_monitor = load_nodes(nodes_path)
    edges = load_edges(edges_path)
    coords = build_circle_layout(node_ids)
    node_to_idx = {nid: i for i, nid in enumerate(node_ids)}

    xs = [coords[nid][0] for nid in node_ids]
    ys = [coords[nid][1] for nid in node_ids]
    colors = []
    for nid in node_ids:
        if is_malicious.get(nid, False):
            colors.append("red")
        elif is_monitor.get(nid, False):
            colors.append("blue")
        else:
            colors.append("black")

    segments = []
    for n1, n2 in edges:
        if n1 in coords and n2 in coords:
            segments.append([coords[n1], coords[n2]])

    plt.ion()
    fig, ax = plt.subplots(figsize=(10, 10))
    if segments:
        lines = LineCollection(segments, colors="gray", linewidths=0.2, alpha=0.3)
        ax.add_collection(lines)
    route_lines = LineCollection([], linewidths=2.0, alpha=0.95)
    ax.add_collection(route_lines)
    ax.scatter(xs, ys, c=colors, s=6, alpha=0.9)
    highlight = ax.scatter([], [], s=70, facecolors="none", edgecolors="yellow", linewidths=1.5)
    info_text = ax.text(0.01, 0.01, "", transform=ax.transAxes, fontsize=10, va="bottom", ha="left")
    ax.set_title("CLoTH Simple Live View")
    ax.set_xticks([])
    ax.set_yticks([])
    ax.set_aspect("equal")
    ax.set_xlim(-1.1, 1.1)
    ax.set_ylim(-1.1, 1.1)
    fig.tight_layout()

    finished = False
    while plt.fignum_exists(fig.number):
        state = read_state(state_path)
        if state is not None:
            nid = state["node_id"]
            if nid in node_to_idx:
                i = node_to_idx[nid]
                highlight.set_offsets([[xs[i], ys[i]]])
            else:
                highlight.set_offsets([])
            pct = 0.0
            if state["total"] > 0:
                pct = 100.0 * float(state["completed"]) / float(state["total"])
            info_text.set_text(
                f"progress={state['completed']}/{state['total']} ({pct:.2f}%)\n"
                f"time={state['time']} event={state['event']} payment={state['payment_id']} node={state['node_id']}"
            )
            route_edges = parse_route_edges(state.get("route", ""))
            route_segments = []
            for n1, n2 in route_edges:
                if n1 in coords and n2 in coords:
                    route_segments.append([coords[n1], coords[n2]])
            route_lines.set_segments(route_segments)
            if route_segments:
                color = plt.cm.tab20(state["payment_id"] % 20 if state["payment_id"] >= 0 else 0)
                route_lines.set_color([color])
            else:
                route_lines.set_color([(0.0, 0.0, 0.0, 0.0)])

        fig.canvas.draw_idle()
        plt.pause(0.2)

        if (not finished) and is_finished(progress_path):
            finished = True
            info_text.set_text(info_text.get_text() + "\nSimulation finished. Close window to continue.")
            fig.canvas.draw_idle()

        if finished:
            # Keep this window open until the user closes it.
            continue

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
