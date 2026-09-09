import pandas as pd
import networkx as nx
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

DATA_DIR = Path("data/raw")
OUTPUT_DIR = Path("data/processed")

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# COMMUNICATION LAYER
# ============================================================

print()
print("=" * 60)
print("        MULTI-LAYER NETWORK ANALYSIS")
print("=" * 60)


print()
print("1. Creating Communication Layer...")


cdr = pd.read_csv(
    DATA_DIR / "cdr_records.csv"
)


communication_graph = nx.DiGraph()


for _, row in cdr.iterrows():

    caller = row["caller_person_id"]
    receiver = row["receiver_person_id"]

    communication_graph.add_edge(
        caller,
        receiver,
        relationship="CALLED",
        duration_seconds=row[
            "duration_seconds"
        ],
        call_date=row[
            "call_date"
        ]
    )


print(
    "Communication nodes:",
    communication_graph.number_of_nodes()
)

print(
    "Communication edges:",
    communication_graph.number_of_edges()
)


# ============================================================
# FINANCIAL LAYER
# ============================================================

print()
print("2. Creating Financial Layer...")


transactions = pd.read_csv(
    DATA_DIR / "transactions.csv"
)


financial_graph = nx.DiGraph()


for _, row in transactions.iterrows():

    sender = row["sender_person_id"]
    receiver = row["receiver_person_id"]

    financial_graph.add_edge(
        sender,
        receiver,
        relationship="TRANSFERRED_MONEY",
        amount=row["amount"],
        transaction_date=row[
            "transaction_date"
        ],
        transaction_type=row[
            "transaction_type"
        ]
    )


print(
    "Financial nodes:",
    financial_graph.number_of_nodes()
)

print(
    "Financial edges:",
    financial_graph.number_of_edges()
)


# ============================================================
# LOCATION LAYER
# ============================================================

print()
print("3. Creating Location Layer...")


location_events = pd.read_csv(
    DATA_DIR / "location_events.csv"
)


location_graph = nx.Graph()


for _, row in location_events.iterrows():

    person = row["person_id"]
    location = row["location_id"]

    location_graph.add_edge(
        person,
        location,
        relationship="VISITED",
        event_date=row[
            "event_date"
        ]
    )


print(
    "Location nodes:",
    location_graph.number_of_nodes()
)

print(
    "Location edges:",
    location_graph.number_of_edges()
)


# ============================================================
# VEHICLE LAYER
# ============================================================

print()
print("4. Creating Vehicle Layer...")


vehicles = pd.read_csv(
    DATA_DIR / "vehicles.csv"
)


vehicle_graph = nx.Graph()


for _, row in vehicles.iterrows():

    person = row["owner_person_id"]
    vehicle = row["vehicle_id"]

    vehicle_graph.add_edge(
        person,
        vehicle,
        relationship="OWNS_VEHICLE"
    )


print(
    "Vehicle nodes:",
    vehicle_graph.number_of_nodes()
)

print(
    "Vehicle edges:",
    vehicle_graph.number_of_edges()
)


# ============================================================
# CASE LAYER
# ============================================================

print()
print("5. Creating Case Layer...")


case_associations = pd.read_csv(
    DATA_DIR / "case_associations.csv"
)


case_graph = nx.Graph()


for _, row in case_associations.iterrows():

    person = row["person_id"]
    case = row["case_id"]

    case_graph.add_edge(
        person,
        case,
        relationship=row[
            "relationship"
        ]
    )


print(
    "Case nodes:",
    case_graph.number_of_nodes()
)

print(
    "Case edges:",
    case_graph.number_of_edges()
)


# ============================================================
# COMBINED PERSON NETWORK
# ============================================================

print()
print("6. Creating Combined Person Network...")


combined_graph = nx.DiGraph()


# Communication relationships

for source, target, data in communication_graph.edges(
    data=True
):

    combined_graph.add_edge(
        source,
        target,
        layer="Communication",
        relationship="CALLED"
    )


# Financial relationships

for source, target, data in financial_graph.edges(
    data=True
):

    if combined_graph.has_edge(
        source,
        target
    ):

        combined_graph[source][target][
            "financial"
        ] = True

    else:

        combined_graph.add_edge(
            source,
            target,
            layer="Financial",
            relationship="TRANSFERRED_MONEY"
        )


print(
    "Combined person nodes:",
    combined_graph.number_of_nodes()
)

print(
    "Combined person edges:",
    combined_graph.number_of_edges()
)


# ============================================================
# SAVE LAYERS
# ============================================================

print()
print("7. Saving network layers...")


nx.write_graphml(
    communication_graph,
    OUTPUT_DIR / "communication_layer.graphml"
)


nx.write_graphml(
    financial_graph,
    OUTPUT_DIR / "financial_layer.graphml"
)


nx.write_graphml(
    location_graph,
    OUTPUT_DIR / "location_layer.graphml"
)


nx.write_graphml(
    vehicle_graph,
    OUTPUT_DIR / "vehicle_layer.graphml"
)


nx.write_graphml(
    case_graph,
    OUTPUT_DIR / "case_layer.graphml"
)


nx.write_graphml(
    combined_graph,
    OUTPUT_DIR / "combined_person_network.graphml"
)


# ============================================================
# SUMMARY
# ============================================================

summary = pd.DataFrame({

    "Layer": [
        "Communication",
        "Financial",
        "Location",
        "Vehicle",
        "Case"
    ],

    "Nodes": [
        communication_graph.number_of_nodes(),
        financial_graph.number_of_nodes(),
        location_graph.number_of_nodes(),
        vehicle_graph.number_of_nodes(),
        case_graph.number_of_nodes()
    ],

    "Edges": [
        communication_graph.number_of_edges(),
        financial_graph.number_of_edges(),
        location_graph.number_of_edges(),
        vehicle_graph.number_of_edges(),
        case_graph.number_of_edges()
    ]

})


summary.to_csv(
    OUTPUT_DIR / "multi_layer_summary.csv",
    index=False
)


print()
print("=" * 60)
print("        MULTI-LAYER ANALYSIS COMPLETED")
print("=" * 60)

print()
print(summary)

print()
print(
    "Files saved in:",
    OUTPUT_DIR.resolve()
)

print()