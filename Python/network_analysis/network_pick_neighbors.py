import networkx as nx
import pandas as pd

# CSVファイル読み込み
nodes_df = pd.read_csv("network_analysis/nodes_ln.csv")
edges_df = pd.read_csv("network_analysis/edges_ln.csv")

# グラフ生成（無向グラフ想定）
G = nx.Graph()
G.add_nodes_from(nodes_df['id'])
G.add_edges_from(edges_df[['from_node_id', 'to_node_id']].values)

# 一番次数が大きいノードを取得
hub_node, hub_degree = max(G.degree, key=lambda x: x[1])

# 隣接ノードを取得
neighbors = list(G.neighbors(hub_node))

# 隣接ノードのうち次数が5以下のノード
low_deg_nodes = [(n, G.degree[n]) for n in neighbors if G.degree[n] <= 5]

# hub_node自身も追加
low_deg_nodes.append((hub_node, hub_degree))

# DataFrameに変換して保存
df = pd.DataFrame(low_deg_nodes, columns=["node_id", "degree"])
df.to_csv("network_analysis/output/low_degree_neighbors.csv", index=False, encoding="utf-8-sig")

print(f"ぷよよーん！{len(df)}件のノードを出力したのりゃ〜📦✨")
