import pandas as pd
import networkx as nx
from pathlib import Path


# ============================================================
# FOLDER PATHS
# ============================================================

DATA_DIR = Path("data/raw")
OUTPUT_DIR = Path("data/processed")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# CREATE CRIMINAL NETWORK GRAPH
# ============================================================

G = nx.MultiDiGraph()


# ============================================================
# 1. PERSONS
# ============================================================

persons = pd.read_csv(DATA_DIR / "persons.csv")

for _, row in persons.iterrows():

    G.add_node(
        row["person_id"],
        type="Person",
        name=row["name"],
        age=row["age"],
        gender=row["gender"],
        occupation=row["occupation"],
        city=row["city"]
    )


# ============================================================
# 2. PHONES
# ============================================================

phones = pd.read_csv(DATA_DIR / "phones.csv")

for _, row in phones.iterrows():

    G.add_node(
        row["phone_id"],
        type="Phone",
        phone_number=row["phone_number"],
        operator=row["operator"]
    )

    G.add_edge(
        row["person_id"],
        row["phone_id"],
        relationship="OWNS"
    )


# ============================================================
# 3. VEHICLES
# ============================================================

vehicles = pd.read_csv(DATA_DIR / "vehicles.csv")

for _, row in vehicles.iterrows():

    G.add_node(
        row["vehicle_id"],
        type="Vehicle",
        registration_number=row["registration_number"],
        vehicle_type=row["vehicle_type"]
    )

    G.add_edge(
        row["owner_person_id"],
        row["vehicle_id"],
        relationship="OWNS"
    )


# ============================================================
# 4. BANK ACCOUNTS
# ============================================================

banks = pd.read_csv(DATA_DIR / "bank_accounts.csv")

for _, row in banks.iterrows():

    G.add_node(
        row["account_id"],
        type="BankAccount",
        account_number=row["account_number"],
        bank=row["bank"]
    )

    G.add_edge(
        row["person_id"],
        row["account_id"],
        relationship="OWNS"
    )


# ============================================================
# 5. ORGANIZATIONS
# ============================================================

organizations = pd.read_csv(DATA_DIR / "organizations.csv")

for _, row in organizations.iterrows():

    G.add_node(
        row["organization_id"],
        type="Organization",
        name=row["name"],
        organization_type=row["type"],
        city=row["city"]
    )


# ============================================================
# 6. LOCATIONS
# ============================================================

locations = pd.read_csv(DATA_DIR / "locations.csv")

for _, row in locations.iterrows():

    G.add_node(
        row["location_id"],
        type="Location",
        name=row["location_name"],
        city=row["city"],
        latitude=row["latitude"],
        longitude=row["longitude"]
    )


# ============================================================
# 7. CASES / FIR
# ============================================================

cases = pd.read_csv(DATA_DIR / "cases.csv")

for _, row in cases.iterrows():

    G.add_node(
        row["case_id"],
        type="Case",
        fir_number=row["fir_number"],
        crime_type=row["crime_type"],
        case_date=row["case_date"]
    )

    # Case occurred at location
    G.add_edge(
        row["case_id"],
        row["location_id"],
        relationship="OCCURRED_AT"
    )


# ============================================================
# 8. DEVICES
# ============================================================

devices = pd.read_csv(DATA_DIR / "devices.csv")

for _, row in devices.iterrows():

    G.add_node(
        row["device_id"],
        type="Device",
        device_type=row["device_type"]
    )

    G.add_edge(
        row["person_id"],
        row["device_id"],
        relationship="USES"
    )


# ============================================================
# 9. CDR / CALL RECORDS
# ============================================================

cdr = pd.read_csv(DATA_DIR / "cdr_records.csv")

for _, row in cdr.iterrows():

    G.add_edge(
        row["caller_person_id"],
        row["receiver_person_id"],
        relationship="CALLED",
        duration_seconds=row["duration_seconds"],
        call_date=row["call_date"]
    )


# ============================================================
# 10. FINANCIAL TRANSACTIONS
# ============================================================

transactions = pd.read_csv(DATA_DIR / "transactions.csv")

for _, row in transactions.iterrows():

    G.add_edge(
        row["sender_person_id"],
        row["receiver_person_id"],
        relationship="TRANSFERRED_MONEY",
        amount=row["amount"],
        transaction_date=row["transaction_date"],
        transaction_type=row["transaction_type"]
    )


# ============================================================
# 11. VEHICLE EVENTS
# ============================================================

vehicle_events = pd.read_csv(DATA_DIR / "vehicle_events.csv")

for _, row in vehicle_events.iterrows():

    G.add_edge(
        row["person_id"],
        row["vehicle_id"],
        relationship="USED_VEHICLE",
        location_id=row["location_id"],
        event_date=row["event_date"]
    )


# ============================================================
# 12. LOCATION EVENTS
# ============================================================

location_events = pd.read_csv(DATA_DIR / "location_events.csv")

for _, row in location_events.iterrows():

    G.add_edge(
        row["person_id"],
        row["location_id"],
        relationship="VISITED",
        event_date=row["event_date"]
    )


# ============================================================
# 13. SURVEILLANCE EVENTS
# ============================================================

surveillance = pd.read_csv(DATA_DIR / "surveillance_events.csv")

for _, row in surveillance.iterrows():

    G.add_edge(
        row["person_id"],
        row["location_id"],
        relationship="SURVEILLANCE_OBSERVED",
        observation=row["observation"],
        observation_date=row["observation_date"]
    )


# ============================================================
# 14. CASE ASSOCIATIONS
# ============================================================

associations = pd.read_csv(DATA_DIR / "case_associations.csv")

for _, row in associations.iterrows():

    G.add_edge(
        row["person_id"],
        row["case_id"],
        relationship=row["relationship"]
    )


# ============================================================
# SAVE GRAPH
# ============================================================

output_file = OUTPUT_DIR / "criminal_network.graphml"

nx.write_graphml(G, output_file)


# ============================================================
# DISPLAY RESULTS
# ============================================================

print()
print("==============================================")
print("       CRIMINAL NETWORK CREATED")
print("==============================================")

print("Total Nodes :", G.number_of_nodes())
print("Total Edges :", G.number_of_edges())

print()
print("Graph saved successfully!")
print("Location:", output_file)

print()
print("==============================================")
print("       NODE TYPES")
print("==============================================")

node_types = {}

for _, data in G.nodes(data=True):

    node_type = data.get("type", "Unknown")

    node_types[node_type] = node_types.get(node_type, 0) + 1

for node_type, count in node_types.items():

    print(f"{node_type:20} : {count}")

print()
print("==============================================")
print("Graph building completed successfully!")
print("==============================================")
