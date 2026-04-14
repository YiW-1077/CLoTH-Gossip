import networkx as nx
import pandas as pd
import os
# ディレクトリ
input_dir = "make_network_files/input"
output_dir = "make_network_files/output"

# 入力ファイル読み込み
nodes_df = pd.read_csv(os.path.join(input_dir, "nodes_ln.csv"))
edges_df = pd.read_csv(os.path.join(input_dir, "edges_ln.csv"))

# グラフ生成（無向グラフ）
G = nx.Graph()
G.add_nodes_from(nodes_df['id'])
G.add_edges_from(edges_df[['from_node_id', 'to_node_id']].values)

# 上位xつの次数が高いノードを取得
top_x=5

top_x_nodes = sorted(G.degree, key=lambda x: x[1], reverse=True)[:top_x]

# 隣接ノードのうち、次数がx以下のノードを集める（重複排除）
degree=5
low_deg_neighbors = {}
for hub_node, _ in top_x_nodes:
    for neighbor in G.neighbors(hub_node):
        deg = G.degree[neighbor]
        if deg <= degree and neighbor not in low_deg_neighbors:
            low_deg_neighbors[neighbor] = deg


# DataFrame に変換して保存
df = pd.DataFrame(low_deg_neighbors.items(), columns=["node_id", "degree"])
df.to_csv(os.path.join(input_dir, "target_nodes.csv"), index=False)

print(f"上位{top_x}ノードに隣接する次数{degree}以下のノードを {len(df)} 件出力")
