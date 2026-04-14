import networkx as nx
import pandas as pd
import matplotlib.pyplot as plt

# CSVファイル読み込み
nodes_df = pd.read_csv("network_analysis/nodes_ln.csv")
edges_df = pd.read_csv("network_analysis/edges_ln.csv")

# 無向グラフの作成
G = nx.Graph()

# ノード追加
for _, row in nodes_df.iterrows():
    node_id = row['id']
    label = row.get('label', str(node_id))
    G.add_node(node_id, label=label)

# エッジ追加
for _, row in edges_df.iterrows():
    G.add_edge(row['from_node_id'], row['to_node_id'])

# 🌟 ハブノードの抽出
hub_node = max(G.degree, key=lambda x: x[1])[0]
neighbors = list(G.neighbors(hub_node))
sub_nodes = [hub_node] + neighbors
H = G.subgraph(sub_nodes)

# 🌈 色リスト作成
node_colors = []
for node in H.nodes():
    if node == hub_node:
        node_colors.append('red')         # ハブは赤！
    else:
        node_colors.append('orange')      # 近傍はオレンジ！

# レイアウト・ラベル
pos = nx.spring_layout(H, seed=42)
labels = nx.get_node_attributes(H, 'label')

# 描画
plt.figure(figsize=(8, 8))
nx.draw(
    H, pos,
    with_labels=True,
    labels=labels,
    node_color=node_colors,
    edge_color='gray',
    node_size=600,
    font_size=10
)
plt.title(f"ぷよんぷよん！ハブノード {hub_node} を見つけたのりゃ！", fontsize=14)
plt.axis("off")
plt.show()
