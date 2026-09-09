import pandas as pd
import networkx as nx
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

DATA_DIR = Path("data/raw")
PROCESSED_DIR = Path("data/processed")

GRAPH_FILE = PROCESSED_DIR / "criminal_network.graphml"


# ============================================================
# LOAD DATA
# ============================================================

print()
print("=" * 65)
print("             RELATIONSHIP ANALYSIS")
print("=" * 65)


# ------------------------------------------------------------
# Check graph
# ------------------------------------------------------------

if not GRAPH_FILE.exists():

    print()
    print("ERROR: Graph file not found.")
    print()
    print("Run:")
    print("python src/graph_builder.py")
    print()

    exit()


G = nx.read_graphml(GRAPH_FILE)


print()
print("Graph loaded successfully.")

print("Total nodes :", G.number_of_nodes())
print("Total edges :", G.number_of_edges())


# ============================================================
# LOAD CSV FILES
# ============================================================

cdr = pd.read_csv(
    DATA_DIR / "cdr_records.csv"
)

transactions = pd.read_csv(
    DATA_DIR / "transactions.csv"
)

location_events = pd.read_csv(
    DATA_DIR / "location_events.csv"
)

case_associations = pd.read_csv(
    DATA_DIR / "case_associations.csv"
)

vehicles = pd.read_csv(
    DATA_DIR / "vehicles.csv"
)


# ============================================================
# PERSON LIST
# ============================================================

persons = pd.read_csv(
    DATA_DIR / "persons.csv"
)


person_ids = persons["person_id"].astype(str).tolist()


# ============================================================
# FUNCTION:
# COMMUNICATION RELATIONSHIP
# ============================================================

def communication_relationship(
    person_a,
    person_b
):

    calls_ab = cdr[
        (
            (cdr["caller_person_id"] == person_a)
            &
            (cdr["receiver_person_id"] == person_b)
        )
        |
        (
            (cdr["caller_person_id"] == person_b)
            &
            (cdr["receiver_person_id"] == person_a)
        )
    ]


    call_count = len(calls_ab)


    total_duration = calls_ab[
        "duration_seconds"
    ].sum()


    if call_count > 0:

        exists = "YES"

    else:

        exists = "NO"


    return {
        "exists": exists,
        "call_count": call_count,
        "total_duration": total_duration
    }


# ============================================================
# FUNCTION:
# FINANCIAL RELATIONSHIP
# ============================================================

def financial_relationship(
    person_a,
    person_b
):

    transfers = transactions[
        (
            (
                transactions["sender_person_id"]
                == person_a
            )
            &
            (
                transactions["receiver_person_id"]
                == person_b
            )
        )
        |
        (
            (
                transactions["sender_person_id"]
                == person_b
            )
            &
            (
                transactions["receiver_person_id"]
                == person_a
            )
        )
    ]


    transaction_count = len(
        transfers
    )


    total_amount = transfers[
        "amount"
    ].sum()


    if transaction_count > 0:

        exists = "YES"

    else:

        exists = "NO"


    return {
        "exists": exists,
        "transaction_count": transaction_count,
        "total_amount": total_amount
    }


# ============================================================
# FUNCTION:
# COMMON LOCATIONS
# ============================================================

def common_locations(
    person_a,
    person_b
):

    locations_a = set(
        location_events[
            location_events["person_id"]
            == person_a
        ]["location_id"]
    )


    locations_b = set(
        location_events[
            location_events["person_id"]
            == person_b
        ]["location_id"]
    )


    common = (
        locations_a
        &
        locations_b
    )


    return {
        "exists":
            "YES"
            if len(common) > 0
            else "NO",

        "count":
            len(common),

        "locations":
            sorted(
                list(common)
            )
    }


# ============================================================
# FUNCTION:
# COMMON CASES
# ============================================================

def common_cases(
    person_a,
    person_b
):

    cases_a = set(
        case_associations[
            case_associations["person_id"]
            == person_a
        ]["case_id"]
    )


    cases_b = set(
        case_associations[
            case_associations["person_id"]
            == person_b
        ]["case_id"]
    )


    common = (
        cases_a
        &
        cases_b
    )


    return {
        "exists":
            "YES"
            if len(common) > 0
            else "NO",

        "count":
            len(common),

        "cases":
            sorted(
                list(common)
            )
    }


# ============================================================
# FUNCTION:
# COMMON VEHICLES
# ============================================================

def common_vehicles(
    person_a,
    person_b
):

    vehicles_a = set(
        vehicles[
            vehicles["owner_person_id"]
            == person_a
        ]["vehicle_id"]
    )


    vehicles_b = set(
        vehicles[
            vehicles["owner_person_id"]
            == person_b
        ]["vehicle_id"]
    )


    common = (
        vehicles_a
        &
        vehicles_b
    )


    return {
        "exists":
            "YES"
            if len(common) > 0
            else "NO",

        "count":
            len(common),

        "vehicles":
            sorted(
                list(common)
            )
    }


# ============================================================
# CREATE PERSON-ONLY GRAPH
# ============================================================

person_graph = nx.DiGraph()


for person in person_ids:

    if person in G.nodes:

        person_graph.add_node(
            person
        )


# ------------------------------------------------------------
# Add direct Person → Person relationships
# ------------------------------------------------------------

for source, target, data in G.edges(
    data=True
):

    if (
        source in person_ids
        and
        target in person_ids
    ):

        person_graph.add_edge(
            source,
            target,
            relationship=data.get(
                "relationship",
                "RELATED"
            )
        )


# ============================================================
# FUNCTION:
# SHORTEST PATH
# ============================================================

def find_shortest_path(
    person_a,
    person_b
):

    # Convert to undirected graph
    # because relationship can exist
    # in either direction.

    undirected = (
        person_graph
        .to_undirected()
    )


    try:

        path = nx.shortest_path(
            undirected,
            source=person_a,
            target=person_b
        )

        return path

    except nx.NetworkXNoPath:

        return []


    except nx.NodeNotFound:

        return []


# ============================================================
# FUNCTION:
# RELATIONSHIP STRENGTH
# ============================================================

def calculate_relationship_strength(
    communication,
    financial,
    locations,
    cases,
    vehicles,
    shortest_path
):

    score = 0


    # --------------------------------------------------------
    # Communication
    # --------------------------------------------------------

    if communication["call_count"] > 0:

        score += 25


    if communication["call_count"] >= 10:

        score += 10


    # --------------------------------------------------------
    # Financial
    # --------------------------------------------------------

    if financial["transaction_count"] > 0:

        score += 25


    if financial["transaction_count"] >= 5:

        score += 10


    # --------------------------------------------------------
    # Common locations
    # --------------------------------------------------------

    if locations["count"] > 0:

        score += 10


    if locations["count"] >= 3:

        score += 5


    # --------------------------------------------------------
    # Common cases
    # --------------------------------------------------------

    if cases["count"] > 0:

        score += 10


    # --------------------------------------------------------
    # Common vehicles
    # --------------------------------------------------------

    if vehicles["count"] > 0:

        score += 5


    # --------------------------------------------------------
    # Direct connection
    # --------------------------------------------------------

    if (
        len(shortest_path) == 2
    ):

        score += 10


    # Maximum = 100

    return min(
        score,
        100
    )


# ============================================================
# MAIN ANALYSIS FUNCTION
# ============================================================

def analyze_relationship(
    person_a,
    person_b
):

    print()
    print("-" * 65)

    print(
        "Analyzing:",
        person_a,
        "<---->",
        person_b
    )

    print("-" * 65)


    # ========================================================
    # COMMUNICATION
    # ========================================================

    communication = communication_relationship(
        person_a,
        person_b
    )


    # ========================================================
    # FINANCIAL
    # ========================================================

    financial = financial_relationship(
        person_a,
        person_b
    )


    # ========================================================
    # LOCATIONS
    # ========================================================

    locations = common_locations(
        person_a,
        person_b
    )


    # ========================================================
    # CASES
    # ========================================================

    cases = common_cases(
        person_a,
        person_b
    )


    # ========================================================
    # VEHICLES
    # ========================================================

    common_vehicle_data = common_vehicles(
        person_a,
        person_b
    )


    # ========================================================
    # SHORTEST PATH
    # ========================================================

    shortest_path = find_shortest_path(
        person_a,
        person_b
    )


    # ========================================================
    # RELATIONSHIP STRENGTH
    # ========================================================

    strength = calculate_relationship_strength(

        communication,

        financial,

        locations,

        cases,

        common_vehicle_data,

        shortest_path
    )


    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    print()

    print("COMMUNICATION")
    print(
        "Relationship:",
        communication["exists"]
    )
    print(
        "Calls:",
        communication["call_count"]
    )
    print(
        "Total duration:",
        communication["total_duration"],
        "seconds"
    )


    print()

    print("FINANCIAL")
    print(
        "Relationship:",
        financial["exists"]
    )
    print(
        "Transactions:",
        financial["transaction_count"]
    )
    print(
        "Total amount:",
        financial["total_amount"]
    )


    print()

    print("COMMON LOCATIONS")
    print(
        "Relationship:",
        locations["exists"]
    )
    print(
        "Common locations:",
        locations["count"]
    )

    if locations["locations"]:

        print(
            "Location IDs:",
            ", ".join(
                locations["locations"]
            )
        )


    print()

    print("COMMON CASES")
    print(
        "Relationship:",
        cases["exists"]
    )
    print(
        "Common cases:",
        cases["count"]
    )

    if cases["cases"]:

        print(
            "Case IDs:",
            ", ".join(
                cases["cases"]
            )
        )


    print()

    print("COMMON VEHICLES")
    print(
        "Relationship:",
        common_vehicle_data["exists"]
    )
    print(
        "Common vehicles:",
        common_vehicle_data["count"]
    )


    print()

    print("SHORTEST PATH")

    if shortest_path:

        print(
            " → ".join(
                shortest_path
            )
        )

    else:

        print(
            "No path found."
        )


    print()

    print("=" * 65)

    print(
        "RELATIONSHIP STRENGTH:",
        strength,
        "/ 100"
    )

    print("=" * 65)


    return {

        "person_a":
            person_a,

        "person_b":
            person_b,

        "communication":
            communication,

        "financial":
            financial,

        "locations":
            locations,

        "cases":
            cases,

        "vehicles":
            common_vehicle_data,

        "shortest_path":
            shortest_path,

        "relationship_strength":
            strength
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    # Change these two IDs if required.

    PERSON_A = "P001"

    PERSON_B = "P002"


    result = analyze_relationship(
        PERSON_A,
        PERSON_B
    )