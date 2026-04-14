import networkx as nx
import pandas as pd
import os

# 出力ディレクトリを作成（既にある場合は無視）
os.makedirs("network_analysis/output", exist_ok=True)

# CSVファイル読み込み
nodes_df = pd.read_csv("network_analysis/nodes_ln.csv")
edges_df = pd.read_csv("network_analysis/edges_ln.csv")

# 有向グラフの作成
G = nx.DiGraph()

# ノードの追加
for _, row in nodes_df.iterrows():
    G.add_node(row['id'])

# エッジの追加（fee_baseを属性として追加）
for _, row in edges_df.iterrows():
    from_node = row['from_node_id']
    to_node = row['to_node_id']
    fee_base = row['fee_base']
    G.add_edge(from_node, to_node, fee_base=fee_base)

# 重みを作成：PageRank用（fee_baseの逆数、0なら1）
for u, v, data in G.edges(data=True):
    fee = data['fee_base']
    data['weight'] = 1 / fee if fee > 0 else 1

# 重みを作成：PageRank用（fee_baseをスケーリングしてから逆数化）
fees = [data['fee_base'] for _, _, data in G.edges(data=True)]
max_fee = max(fees)
eps = 1e-6  # 0除け
for u, v, data in G.edges(data=True):
    fee = data['fee_base']
    # スケール後に逆数にして安定化（1～1000の範囲などにする）
    scaled_fee = fee / max_fee + eps  # eps〜1になる
    data['weight_pagerank'] = 1 / scaled_fee  # 大きいfee = 小さいweight
# ---------- 中心性指標の計算 ---------- #

# 1. PageRank（逆fee_baseを重みとして使用）
pagerank_a = nx.pagerank(G, weight='weight')

pagerank_b = nx.pagerank(G, weight='weight_pagerank')

# 2. Degree Centrality（次数中心性）
degree_centrality = nx.degree_centrality(G)/2

# 3. Closeness Centrality（近接中心性）
closeness_centrality = nx.closeness_centrality(G, distance = 'fee_base')

# # 4. Betweenness Centrality（媒介中心性）
# betweenness_centrality = nx.betweenness_centrality(G, weight = 'fee_base', normalized=True)

# ---------- 結果表示（上位50件） ---------- #

def print_top(dictionary, title):
    print(f"\n--- {title} (Top 50) ---")
    top_nodes = sorted(dictionary.items(), key=lambda x: x[1], reverse=True)[:50]
    for node, value in top_nodes:
        print(f"Node {node}: {value:.6f}")

# print(nx.number_of_nodes(G))
# print(nx.number_of_edges(G))
# print_top(pagerank_a, "PageRank")
# print_top(pagerank_b, "PageRank")
# print_top(degree_centrality, "Degree Centrality")
# print_top(closeness_centrality, "Closeness Centrality")
# print_top(betweenness_centrality, "Betweenness Centrality")

# ---------- 結果をCSVで保存 ---------- #
import csv
def save_to_csv(centrality_dict, filename):
    # 中心性辞書をスコア順に降順ソート
    sorted_items = sorted(centrality_dict.items(), key=lambda x: x[1], reverse=True)
    
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Index', 'Node_ID', 'Centrality_Value'])
        
        for i, (node, value) in enumerate(sorted_items, start=1):
            writer.writerow([i, node, value])
save_to_csv(pagerank_a, "network_analysis/output/pagerank.csv")
save_to_csv(pagerank_b, "network_analysis/output/pagerank_weightscaled.csv")
save_to_csv(degree_centrality, "network_analysis/output/degree_centrality.csv")
save_to_csv(closeness_centrality, "network_analysis/output/closeness_centrality.csv")
# save_to_csv(betweenness_centrality, "network_analysis/output/betweenness_centrality.csv")
