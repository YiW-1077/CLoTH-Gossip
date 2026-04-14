import networkx as nx
import pandas as pd
import numpy as np

# --- グラフ読み込み ---
nodes_df = pd.read_csv("network_analysis/nodes_ln.csv")
edges_df = pd.read_csv("network_analysis/edges_ln.csv")

G = nx.Graph()
for _, row in nodes_df.iterrows():
    G.add_node(row['id'])
for _, row in edges_df.iterrows():
    G.add_edge(row['from_node_id'], row['to_node_id'])

# --- ノードごとの次数 ---
degrees = [d for _, d in G.degree()]
degree_counts = np.bincount(degrees)
degree_vals = np.nonzero(degree_counts)[0]
counts = degree_counts[degree_vals]

# --- CSVとして保存 ---
df = pd.DataFrame({
    'degree': degree_vals,
    'count': counts
})
df.to_csv("network_analysis/output/degree_distribution.csv", index=False, encoding='utf-8-sig')

print("ぷよん！degree_distribution.csv を保存したのりゃ📄")

from collections import Counter

# --- 最大次数ノード（ハブノード）を取得 ---
hub_node = max(G.degree, key=lambda x: x[1])[0]
print(f"ぷよん！ハブノードは: {hub_node}")

# --- 隣接ノードの次数を収集 ---
neighbor_degrees = [G.degree[n] for n in G.neighbors(hub_node)]

# --- 頻度分布（ヒストグラムデータ）を作成 ---
degree_counter = Counter(neighbor_degrees)
df = pd.DataFrame(degree_counter.items(), columns=['degree', 'count']).sort_values('degree')

# --- CSVとして保存 ---
df.to_csv("network_analysis/output/hub_neighbors_degree_distribution.csv", index=False, encoding='utf-8-sig')

print("ぷよよーん！hub_neighbors_degree_distribution.csv を出力したのりゃ📄✨")

# --- 次数上位5ノードを取得 ---
top5_nodes = sorted(G.degree, key=lambda x: x[1], reverse=True)[:5]
top5_ids = [node for node, _ in top5_nodes]

# --- 隣接ノードの次数をすべて取得（重複あり） ---
neighbor_degrees = []
for hub_node in top5_ids:
    neighbors = G.neighbors(hub_node)
    neighbor_degrees += [G.degree[n] for n in neighbors]

# --- 頻度分布（ヒストグラムデータ）を作成 ---
degree_counter = Counter(neighbor_degrees)
df = pd.DataFrame(degree_counter.items(), columns=['degree', 'count']).sort_values('degree')

# --- CSVに保存 ---
df.to_csv("network_analysis/output/top5hubs_neighbors_degree_distribution.csv", index=False, encoding='utf-8-sig')

print("ぷよよーん！top5hubs_neighbors_degree_distribution.csv を出力したのりゃ📄✨")