import networkx as nx
import pandas as pd
from pathlib import Path


# ============================================================
# LOAD GRAPH
# ============================================================

GRAPH_FILE = Path("data/processed/criminal_network.graphml")

G = nx.read_graphml(GRAPH_FILE)

print("==============================================")
print("       CRIMINAL NETWORK ANALYSIS")
print("==============================================")

print("Total Nodes:", G.number_of_nodes())
print("Total Edges:", G.number_of_edges())


# ============================================================
# CREATE PERSON-ONLY GRAPH
# ============================================================

person_nodes = [
    node
    for node, data in G.nodes(data=True)
    if data.get("type") == "Person"
]

person_graph = G.subgraph(person_nodes).copy()

# Convert MultiDiGraph to DiGraph
# Multiple calls/transactions between two people
# are represented as one connection for centrality analysis.

P = nx.DiGraph()

for source, target in person_graph.edges():

    if source != target:
        P.add_edge(source, target)


# ============================================================
# ADD ALL PERSONS
# ============================================================

for person in person_nodes:

    if person not in P:
        P.add_node(person)


print()
print("Person Network Nodes:", P.number_of_nodes())
print("Person Network Edges:", P.number_of_edges())


# ============================================================
# 1. DEGREE CENTRALITY
# ============================================================

print()
print("==============================================")
print("       1. DEGREE CENTRALITY")
print("==============================================")

degree = nx.degree_centrality(P)

degree_result = sorted(
    degree.items(),
    key=lambda x: x[1],
    reverse=True
)

print()
print("Top 10 People by Degree Centrality:")
print()

for rank, (person, score) in enumerate(degree_result[:10], start=1):

    name = G.nodes[person].get("name", person)

    print(
        f"{rank:2}. {person} - {name} "
        f"Score: {score:.4f}"
    )


# ============================================================
# 2. PAGERANK
# ============================================================

print()
print("==============================================")
print("       2. PAGERANK")
print("==============================================")

pagerank = nx.pagerank(P)

pagerank_result = sorted(
    pagerank.items(),
    key=lambda x: x[1],
    reverse=True
)

print()
print("Top 10 People by PageRank:")
print()

for rank, (person, score) in enumerate(pagerank_result[:10], start=1):

    name = G.nodes[person].get("name", person)

    print(
        f"{rank:2}. {person} - {name} "
        f"Score: {score:.4f}"
    )


# ============================================================
# 3. BETWEENNESS CENTRALITY
# ============================================================

print()
print("==============================================")
print("       3. BETWEENNESS CENTRALITY")
print("==============================================")

# Convert to undirected graph because we are looking
# for people acting as bridges between groups.

U = P.to_undirected()

betweenness = nx.betweenness_centrality(U)

betweenness_result = sorted(
    betweenness.items(),
    key=lambda x: x[1],
    reverse=True
)

print()
print("Top 10 People by Betweenness Centrality:")
print()

for rank, (person, score) in enumerate(
    betweenness_result[:10],
    start=1
):

    name = G.nodes[person].get("name", person)

    print(
        f"{rank:2}. {person} - {name} "
        f"Score: {score:.4f}"
    )


# ============================================================
# SAVE RESULTS
# ============================================================

results = []

for person in person_nodes:

    results.append({
        "person_id": person,
        "name": G.nodes[person].get("name", ""),
        "degree_centrality": degree.get(person, 0),
        "pagerank": pagerank.get(person, 0),
        "betweenness_centrality": betweenness.get(person, 0)
    })


results_df = pd.DataFrame(results)

results_df = results_df.sort_values(
    "degree_centrality",
    ascending=False
)


# ============================================================
# CREATE PROCESSED FOLDER
# ============================================================

Path("data/processed").mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# SAVE CSV
# ============================================================

output_file = Path(
    "data/processed/graph_analysis_results.csv"
)

results_df.to_csv(
    output_file,
    index=False
)


# ============================================================
# COMPLETION
# ============================================================

print()
print("==============================================")
print("       ANALYSIS COMPLETED")
print("==============================================")

print()
print("Results saved to:")

print(output_file)

print()
print("Generated columns:")

print("• person_id")
print("• name")
print("• degree_centrality")
print("• pagerank")
print("• betweenness_centrality")

print()
print("==============================================")