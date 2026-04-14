import pandas as pd
import networkx as nx
import os
import random

# ディレクトリ
input_dir = "make_network_files/input"
output_dir = "make_network_files/output"

# 入力ファイル読み込み
nodes_df = pd.read_csv(os.path.join(input_dir, "nodes_ln.csv"))
edges_df = pd.read_csv(os.path.join(input_dir, "edges_ln.csv"))

# ⭐ ランダムに選ぶターゲットノードの数
num_target_nodes = 4357

# ランダムサンプリング
if len(nodes_df) >= num_target_nodes:
    target_node_ids = random.sample(list(nodes_df["id"]), num_target_nodes)
else:
    print("ぷぅぅ...指定数よりノードが少ないのりゃ")
    target_node_ids = list(nodes_df["id"])

# DataFrameに変換
target_nodes_df = pd.DataFrame({"node_id": target_node_ids})
target_nodes_df.to_csv(os.path.join(input_dir, "target_nodes.csv"), index=False)

print("ファイル出力")

# 入力ファイル読み込み
nodes_df = pd.read_csv(os.path.join(input_dir, "nodes_ln.csv"))
edges_df = pd.read_csv(os.path.join(input_dir, "edges_ln.csv"))
channels_df = pd.read_csv(os.path.join(input_dir, "channels_ln.csv"))
target_nodes_df = pd.read_csv(os.path.join(input_dir, "target_nodes.csv")) #ここはターゲットノードのファイル名

# 追加するノード数
num_new_nodes = 5

# 新しいノードを作成
if len(nodes_df) > 0:
    max_node_id = nodes_df["id"].max()
else:
    max_node_id = 0

new_node_ids = list(range(max_node_id + 1, max_node_id + 1 + num_new_nodes))
new_nodes_df = pd.DataFrame({"id": new_node_ids})

# nodes.csvを更新
updated_nodes_df = pd.concat([nodes_df, new_nodes_df], ignore_index=True)

# edges.csvのIDの初期値
if len(edges_df) > 0:
    edge_id = edges_df["id"].max() + 1
else:
    edge_id = 1

# channels.csvのIDの初期値
if len(channels_df) > 0:
    channel_id = channels_df["id"].max() + 1
else:
    channel_id = 1

# 既存のエッジをコピー
edges_to_add = []

# 各 target_node に対して、新しいノード1つとだけエッジを作る
for target_node in target_nodes_df["node_id"]:
    new_node_id = random.choice(new_node_ids)
    
    # edge1 (from new_node -> target_node)
    edges_to_add.append({
        "id": edge_id,
        "channel_id": channel_id,
        "counter_edge_id": edge_id + 1,
        "from_node_id": new_node_id,
        "to_node_id": target_node,
        "balance":100000000,
        "fee_base": 0,
        "fee_proportional": 0,
        "min_htlc": 1,
        "timelock": 40
    })
    
    # edge2 (from target_node -> new_node)
    edges_to_add.append({
        "id": edge_id + 1,
        "channel_id": channel_id,
        "counter_edge_id": edge_id,
        "from_node_id": target_node,
        "to_node_id": new_node_id,
        "balance": 100000000,
        "fee_base": 0,
        "fee_proportional": 0,
        "min_htlc": 1,
        "timelock": 40
    })
    
    edge_id += 2
    channel_id += 1

import itertools

# new_node_ids の組み合わせから完全グラフを作る
for node1_id, node2_id in itertools.combinations(new_node_ids, 2):
    # edge1 (from node1 -> node2)
    edges_to_add.append({
        "id": edge_id,
        "channel_id": channel_id,
        "counter_edge_id": edge_id + 1,
        "from_node_id": node1_id,
        "to_node_id": node2_id,
        "balance":100000000,
        "fee_base": 0,
        "fee_proportional": 0,
        "min_htlc": 1,
        "timelock": 40
    })
    
    # edge2 (from node2 -> node1)
    edges_to_add.append({
        "id": edge_id + 1,
        "channel_id": channel_id,
        "counter_edge_id": edge_id,
        "from_node_id": node2_id,
        "to_node_id": node1_id,
        "balance":100000000,
        "fee_base": 0,
        "fee_proportional": 0,
        "min_htlc": 1,
        "timelock": 40
    })
    
    edge_id += 2
    channel_id += 1


# DataFrameに変換
new_edges_df = pd.DataFrame(edges_to_add)

# edges.csvを更新
updated_edges_df = pd.concat([edges_df, new_edges_df], ignore_index=True)

# channels.csvを更新
new_channels = []
for c in new_edges_df["channel_id"].unique():
    # そのchannelに対応する2つのエッジ
    edge_rows = new_edges_df[new_edges_df["channel_id"] == c]
    node1_id = edge_rows.iloc[0]["from_node_id"]
    node2_id = edge_rows.iloc[0]["to_node_id"]
    edge1_id = edge_rows.iloc[0]["id"]
    edge2_id = edge_rows.iloc[1]["id"]
    
    new_channels.append({
        "id": c,
        "edge1_id": edge1_id,
        "edge2_id": edge2_id,
        "node1_id": node1_id,
        "node2_id": node2_id,
        "capacity": 200000000  # balanceの合計
    })

new_channels_df = pd.DataFrame(new_channels)
updated_channels_df = pd.concat([channels_df, new_channels_df], ignore_index=True)

# 出力フォルダ作成
os.makedirs(output_dir, exist_ok=True)

# CSV出力
updated_nodes_df.to_csv(os.path.join(output_dir, f"nodes_ln_rand_{num_target_nodes}_{num_new_nodes}.csv"), index=False)
updated_edges_df.to_csv(os.path.join(output_dir, f"edges_ln_rand_{num_target_nodes}_{num_new_nodes}.csv"), index=False)
updated_channels_df.to_csv(os.path.join(output_dir, f"channels_ln_rand_{num_target_nodes}_{num_new_nodes}.csv"), index=False)

print("ネットワークファイル出力完了")
print(f"新規ノード数:{num_new_nodes},新規チャネル数(ターゲットノード){num_target_nodes}")