import pandas as pd
import networkx as nx
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

DATA_DIR = Path("data/raw")
PROCESSED_DIR = Path("data/processed")

GRAPH_FILE = PROCESSED_DIR / "criminal_network.graphml"
OUTPUT_FILE = PROCESSED_DIR / "investigative_assessment.csv"


# ============================================================
# SETTINGS
# ============================================================

# This is NOT a legal determination.
# It is an investigative relevance score.

ASSESSMENT_THRESHOLD = 60


# ============================================================
# LOAD GRAPH
# ============================================================

print()
print("=" * 60)
print("        INVESTIGATIVE ASSESSMENT")
print("=" * 60)

if not GRAPH_FILE.exists():

    print()
    print("ERROR: Graph file not found.")
    print("Run graph_builder.py first.")
    exit()


G = nx.read_graphml(GRAPH_FILE)

print()
print("Graph loaded successfully.")

print("Nodes :", G.number_of_nodes())
print("Edges :", G.number_of_edges())


# ============================================================
# PERSON NETWORK
# ============================================================

person_nodes = [
    node
    for node, data in G.nodes(data=True)
    if data.get("type") == "Person"
]


person_graph = nx.DiGraph()

person_graph.add_nodes_from(person_nodes)


# Only direct Person -> Person relationships

for source, target, data in G.edges(data=True):

    if source in person_nodes and target in person_nodes:

        person_graph.add_edge(
            source,
            target,
            relationship=data.get(
                "relationship",
                "RELATED"
            )
        )


print()
print("Persons :", len(person_nodes))
print("Person relationships :", person_graph.number_of_edges())


# ============================================================
# GRAPH METRICS
# ============================================================

print()
print("Calculating graph metrics...")


degree = dict(person_graph.degree())

pagerank = nx.pagerank(
    person_graph
)


betweenness = nx.betweenness_centrality(
    person_graph
)


# ============================================================
# LOAD RAW DATA
# ============================================================

cdr = pd.read_csv(
    DATA_DIR / "cdr_records.csv"
)

transactions = pd.read_csv(
    DATA_DIR / "transactions.csv"
)

case_associations = pd.read_csv(
    DATA_DIR / "case_associations.csv"
)

location_events = pd.read_csv(
    DATA_DIR / "location_events.csv"
)

vehicles = pd.read_csv(
    DATA_DIR / "vehicles.csv"
)


# ============================================================
# COMMUNICATION ACTIVITY
# ============================================================

call_count = {}

for person in person_nodes:

    outgoing = (
        cdr["caller_person_id"] == person
    ).sum()

    incoming = (
        cdr["receiver_person_id"] == person
    ).sum()

    call_count[person] = (
        outgoing + incoming
    )


# ============================================================
# FINANCIAL ACTIVITY
# ============================================================

transaction_count = {}

transaction_amount = {}

for person in person_nodes:

    sent = transactions[
        transactions["sender_person_id"] == person
    ]

    received = transactions[
        transactions["receiver_person_id"] == person
    ]

    transaction_count[person] = (
        len(sent) + len(received)
    )

    transaction_amount[person] = (
        sent["amount"].sum()
        +
        received["amount"].sum()
    )


# ============================================================
# CASE ASSOCIATIONS
# ============================================================

case_count = (
    case_associations
    .groupby("person_id")
    .size()
    .to_dict()
)


# ============================================================
# LOCATION ASSOCIATIONS
# ============================================================

location_count = (
    location_events
    .groupby("person_id")
    .size()
    .to_dict()
)


# ============================================================
# VEHICLE OWNERSHIP
# ============================================================

vehicle_count = (
    vehicles
    .groupby("owner_person_id")
    .size()
    .to_dict()
)


# ============================================================
# NORMALIZATION FUNCTION
# ============================================================

def normalize(values):

    series = pd.Series(values, dtype=float)

    minimum = series.min()
    maximum = series.max()

    if maximum == minimum:

        return {
            key: 0
            for key in values
        }

    result = {}

    for key, value in values.items():

        score = (
            (value - minimum)
            /
            (maximum - minimum)
        ) * 100

        result[key] = score

    return result


# ============================================================
# NORMALIZE METRICS
# ============================================================

degree_score = normalize(degree)

pagerank_score = normalize(pagerank)

betweenness_score = normalize(
    betweenness
)

communication_score = normalize(
    call_count
)

financial_score = normalize(
    transaction_amount
)

case_score = normalize(
    case_count
    if case_count
    else {person: 0 for person in person_nodes}
)

location_score = normalize(
    location_count
    if location_count
    else {person: 0 for person in person_nodes}
)


# ============================================================
# FINAL INVESTIGATIVE SCORE
# ============================================================

results = []


for person in person_nodes:

    score = (

        degree_score.get(person, 0)
        * 0.20

        +

        pagerank_score.get(person, 0)
        * 0.15

        +

        betweenness_score.get(person, 0)
        * 0.20

        +

        communication_score.get(person, 0)
        * 0.15

        +

        financial_score.get(person, 0)
        * 0.15

        +

        case_score.get(person, 0)
        * 0.10

        +

        location_score.get(person, 0)
        * 0.05
    )


    # ========================================================
    # SCORE BAND
    # ========================================================

    if score <= 30:

        band = "LOW"

    elif score <= 60:

        band = "MEDIUM"

    elif score <= 80:

        band = "HIGH"

    else:

        band = "VERY HIGH"


    # ========================================================
    # YES / NO ASSESSMENT
    # ========================================================

    assessment = (
        "YES"
        if score >= ASSESSMENT_THRESHOLD
        else "NO"
    )


    # ========================================================
    # PERSON NAME
    # ========================================================

    person_data = G.nodes[person]

    name = person_data.get(
        "name",
        person
    )


    results.append({

        "person_id": person,

        "name": name,

        "degree": degree.get(
            person,
            0
        ),

        "pagerank": pagerank.get(
            person,
            0
        ),

        "betweenness": betweenness.get(
            person,
            0
        ),

        "call_count": call_count.get(
            person,
            0
        ),

        "transaction_count":
            transaction_count.get(
                person,
                0
            ),

        "transaction_amount":
            transaction_amount.get(
                person,
                0
            ),

        "case_count":
            case_count.get(
                person,
                0
            ),

        "location_count":
            location_count.get(
                person,
                0
            ),

        "vehicle_count":
            vehicle_count.get(
                person,
                0
            ),

        "investigative_score":
            round(score, 2),

        "assessment":
            assessment,

        "score_band":
            band
    })


# ============================================================
# CREATE DATAFRAME
# ============================================================

result_df = pd.DataFrame(
    results
)


# Sort highest score first

result_df = result_df.sort_values(
    "investigative_score",
    ascending=False
)


# ============================================================
# SAVE
# ============================================================

result_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# DISPLAY TOP RESULTS
# ============================================================

print()
print("=" * 60)
print("        TOP INVESTIGATIVE RESULTS")
print("=" * 60)

print()

print(
    result_df[
        [
            "person_id",
            "name",
            "investigative_score",
            "assessment",
            "score_band"
        ]
    ].head(20).to_string(
        index=False
    )
)


print()
print("=" * 60)

print(
    "Assessment file saved:"
)

print(
    OUTPUT_FILE.resolve()
)

print("=" * 60)