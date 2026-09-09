import networkx as nx
from pathlib import Path
import html
import json


# ============================================================
# SETTINGS
# ============================================================

INPUT_FILE = Path("data/processed/criminal_network.graphml")
OUTPUT_FILE = Path("data/complete_network.html")

# Number of nodes and edges displayed
MAX_NODES = 150
MAX_EDGES = 500

# ⭐ EDGE SIZE — smaller = thinner
EDGE_WIDTH = 0.7

# Edge transparency
EDGE_OPACITY = 0.45


# ============================================================
# NODE COLORS
# ============================================================

NODE_COLORS = {
    "Person": "#ff6b6b",
    "Phone": "#4dabf7",
    "Vehicle": "#51cf66",
    "BankAccount": "#ffd43b",
    "Organization": "#cc5de8",
    "Location": "#20c997",
    "Case": "#ff922b",
    "Device": "#845ef7",
}


# ============================================================
# LOAD GRAPH
# ============================================================

print()
print("=" * 55)
print("       CRIMINAL NETWORK VISUALIZATION")
print("=" * 55)

if not INPUT_FILE.exists():
    print()
    print("ERROR: Graph file not found!")
    print("Expected:")
    print(INPUT_FILE)
    print()
    print("Run this first:")
    print("python src/graph_builder.py")
    exit()

print()
print("Loading graph...")

G = nx.read_graphml(INPUT_FILE)

print("Total nodes :", G.number_of_nodes())
print("Total edges :", G.number_of_edges())


# ============================================================
# SELECT NODES
# ============================================================

print()
print("Preparing visualization...")


# Prefer Person nodes
person_nodes = [
    n for n, d in G.nodes(data=True)
    if d.get("type") == "Person"
]

other_nodes = [
    n for n in G.nodes()
    if n not in person_nodes
]

selected_nodes = person_nodes + other_nodes

selected_nodes = selected_nodes[:MAX_NODES]

H = G.subgraph(selected_nodes).copy()


# ============================================================
# LIMIT EDGES
# ============================================================

edges = list(H.edges(data=True, keys=True))

if len(edges) > MAX_EDGES:
    edges = edges[:MAX_EDGES]


# ============================================================
# CREATE POSITIONS
# ============================================================

print("Calculating layout...")

# Undirected graph for layout
layout_graph = nx.Graph()

layout_graph.add_nodes_from(H.nodes())

for edge in edges:
    if len(edge) == 4:
        source, target, key, data = edge
    else:
        source, target, data = edge

    if source != target:
        layout_graph.add_edge(source, target)

try:
    positions = nx.spring_layout(
        layout_graph,
        seed=42,
        k=2.5,
        iterations=100
    )
except Exception:
    positions = nx.random_layout(layout_graph, seed=42)


# ============================================================
# NORMALIZE POSITIONS
# ============================================================

xs = [positions[n][0] for n in positions]
ys = [positions[n][1] for n in positions]

min_x = min(xs) if xs else 0
max_x = max(xs) if xs else 1

min_y = min(ys) if ys else 0
max_y = max(ys) if ys else 1

WIDTH = 1400
HEIGHT = 850
MARGIN = 80


def convert_x(x):
    if max_x == min_x:
        return WIDTH / 2

    return MARGIN + (
        (x - min_x) / (max_x - min_x)
    ) * (WIDTH - 2 * MARGIN)


def convert_y(y):
    if max_y == min_y:
        return HEIGHT / 2

    return MARGIN + (
        (y - min_y) / (max_y - min_y)
    ) * (HEIGHT - 2 * MARGIN)


# ============================================================
# CREATE NODE DATA
# ============================================================

nodes_data = []

for node in selected_nodes:

    data = G.nodes[node]

    node_type = data.get("type", "Unknown")

    color = NODE_COLORS.get(
        node_type,
        "#adb5bd"
    )

    x = convert_x(positions[node][0])
    y = convert_y(positions[node][1])

    # Store all available information
    information = {}

    for key, value in data.items():
        information[str(key)] = str(value)

    information["id"] = str(node)
    information["type"] = node_type

    nodes_data.append({
        "id": str(node),
        "label": str(node),
        "type": node_type,
        "color": color,
        "x": x,
        "y": y,
        "information": information
    })


# ============================================================
# CREATE EDGE DATA
# ============================================================

edges_data = []

for edge in edges:

    if len(edge) == 4:
        source, target, key, data = edge
    else:
        source, target, data = edge

    if source not in selected_nodes:
        continue

    if target not in selected_nodes:
        continue

    source_type = G.nodes[source].get(
        "type",
        "Unknown"
    )

    target_type = G.nodes[target].get(
        "type",
        "Unknown"
    )

    # Same color as source node
    edge_color = NODE_COLORS.get(
        source_type,
        "#adb5bd"
    )

    relationship = data.get(
        "relationship",
        data.get(
            "type",
            data.get(
                "relation",
                "RELATED"
            )
        )
    )

    edge_information = {}

    for key, value in data.items():
        edge_information[str(key)] = str(value)

    edge_information["relationship"] = str(
        relationship
    )

    edges_data.append({
        "source": str(source),
        "target": str(target),
        "relationship": str(relationship),
        "color": edge_color,
        "information": edge_information
    })


# ============================================================
# CONVERT DATA TO JSON
# ============================================================

nodes_json = json.dumps(
    nodes_data,
    ensure_ascii=False
)

edges_json = json.dumps(
    edges_data,
    ensure_ascii=False
)


# ============================================================
# HTML
# ============================================================

html_page = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
Criminal Network Analysis
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #f4f6f8;

    color: #212529;

}}

.header {{

    height: 70px;

    background: #1f2937;

    color: white;

    display: flex;

    align-items: center;

    padding: 0 25px;

    font-size: 23px;

    font-weight: bold;

}}

.container {{

    display: flex;

    height: calc(100vh - 70px);

}}

.graph-area {{

    flex: 1;

    background: white;

    overflow: auto;

    position: relative;

}}

#graph {{

    width: 1400px;

    height: 850px;

}}

.side-panel {{

    width: 350px;

    background: #ffffff;

    border-left: 1px solid #ddd;

    padding: 20px;

    overflow-y: auto;

}}

.side-panel h2 {{

    margin-top: 0;

    font-size: 20px;

}}

.info-box {{

    background: #f8f9fa;

    border: 1px solid #ddd;

    border-radius: 8px;

    padding: 12px;

    margin-bottom: 15px;

}}

.info-row {{

    padding: 6px 0;

    border-bottom: 1px solid #eee;

    font-size: 13px;

}}

.info-row:last-child {{

    border-bottom: none;

}}

.info-key {{

    font-weight: bold;

    color: #495057;

}}

.legend {{

    position: absolute;

    top: 15px;

    left: 15px;

    background: rgba(255,255,255,0.95);

    padding: 12px;

    border-radius: 8px;

    border: 1px solid #ddd;

    z-index: 10;

}}

.legend-title {{

    font-weight: bold;

    margin-bottom: 8px;

}}

.legend-item {{

    display: flex;

    align-items: center;

    margin: 5px 0;

    font-size: 13px;

}}

.legend-color {{

    width: 14px;

    height: 14px;

    border-radius: 50%;

    margin-right: 8px;

}}

button {{

    border: none;

    background: #343a40;

    color: white;

    padding: 8px 14px;

    border-radius: 5px;

    cursor: pointer;

    margin-bottom: 10px;

}}

button:hover {{

    background: #212529;

}}

svg {{

    background: white;

}}

.edge {{

    stroke-width: {EDGE_WIDTH};

    opacity: {EDGE_OPACITY};

}}

.node {{

    cursor: pointer;

}}

.node:hover {{

    stroke: #000;

    stroke-width: 2;

}}

.node-label {{

    font-size: 10px;

    pointer-events: none;

    fill: #343a40;

}}

.relationship {{

    font-size: 8px;

    fill: #6c757d;

    pointer-events: none;

}}

.selected {{

    stroke: #000;

    stroke-width: 3;

}}

</style>

</head>


<body>


<div class="header">

    🔎 Criminal Network Analysis System

</div>


<div class="container">


<div class="graph-area">


<div class="legend">

<div class="legend-title">
Entity Types
</div>

<div class="legend-item">

<div class="legend-color"
style="background:#ff6b6b">
</div>

Person

</div>

<div class="legend-item">

<div class="legend-color"
style="background:#4dabf7">
</div>

Phone

</div>

<div class="legend-item">

<div class="legend-color"
style="background:#51cf66">
</div>

Vehicle

</div>

<div class="legend-item">

<div class="legend-color"
style="background:#ffd43b">
</div>

Bank Account

</div>

<div class="legend-item">

<div class="legend-color"
style="background:#cc5de8">
</div>

Organization

</div>

<div class="legend-item">

<div class="legend-color"
style="background:#20c997">
</div>

Location

</div>

<div class="legend-item">

<div class="legend-color"
style="background:#ff922b">
</div>

Case

</div>

<div class="legend-item">

<div class="legend-color"
style="background:#845ef7">
</div>

Device

</div>

</div>


<svg
id="graph"
viewBox="0 0 1400 850"
xmlns="http://www.w3.org/2000/svg">

</svg>


</div>


<div class="side-panel">


<h2>
Node Information
</h2>


<button onclick="clearSelection()">
Clear Selection
</button>


<div id="nodeInfo">

Click a node to see information.

</div>


</div>


</div>


<script>


const nodes = {nodes_json};

const edges = {edges_json};


const svg =
document.getElementById("graph");


const nodeMap = {{}};

nodes.forEach(n => {{

    nodeMap[n.id] = n;

}});


const NS =
"http://www.w3.org/2000/svg";


// ============================================================
// DRAW EDGES
// ============================================================

edges.forEach(edge => {{

    const source =
        nodeMap[edge.source];

    const target =
        nodeMap[edge.target];

    if (!source || !target) {{
        return;
    }}


    const line =
        document.createElementNS(
            NS,
            "line"
        );


    line.setAttribute(
        "x1",
        source.x
    );

    line.setAttribute(
        "y1",
        source.y
    );

    line.setAttribute(
        "x2",
        target.x
    );

    line.setAttribute(
        "y2",
        target.y
    );


    line.setAttribute(
        "stroke",
        edge.color
    );


    line.setAttribute(
        "stroke-width",
        "{EDGE_WIDTH}"
    );


    line.setAttribute(
        "opacity",
        "{EDGE_OPACITY}"
    );


    line.classList.add("edge");


    svg.appendChild(line);

}});


// ============================================================
// DRAW NODES
// ============================================================

nodes.forEach(node => {{

    const group =
        document.createElementNS(
            NS,
            "g"
        );


    group.classList.add("node");


    const circle =
        document.createElementNS(
            NS,
            "circle"
        );


    circle.setAttribute(
        "cx",
        node.x
    );


    circle.setAttribute(
        "cy",
        node.y
    );


    circle.setAttribute(
        "r",
        node.type === "Person"
            ? 8
            : 6
    );


    circle.setAttribute(
        "fill",
        node.color
    );


    circle.setAttribute(
        "stroke",
        "#ffffff"
    );


    circle.setAttribute(
        "stroke-width",
        "1"
    );


    group.appendChild(circle);


    const label =
        document.createElementNS(
            NS,
            "text"
        );


    label.setAttribute(
        "x",
        node.x + 10
    );


    label.setAttribute(
        "y",
        node.y + 3
    );


    label.classList.add(
        "node-label"
    );


    label.textContent =
        node.label;


    group.appendChild(label);


    group.addEventListener(
        "click",
        function(event) {{

            event.stopPropagation();

            selectNode(node.id);

        }}
    );


    svg.appendChild(group);

}});


// ============================================================
// NODE SELECTION
// ============================================================

function selectNode(nodeId) {{

    const node =
        nodeMap[nodeId];


    if (!node) {{
        return;
    }}


    // Remove previous selection

    document
        .querySelectorAll(".selected")
        .forEach(element => {{

            element.classList.remove(
                "selected"
            );

        }});


    // Find selected node

    const circles =
        document.querySelectorAll(
            ".node circle"
        );


    circles.forEach(circle => {{

        const cx =
            parseFloat(
                circle.getAttribute("cx")
            );

        const cy =
            parseFloat(
                circle.getAttribute("cy")
            );


        if (
            Math.abs(cx - node.x) < 0.1 &&
            Math.abs(cy - node.y) < 0.1
        ) {{

            circle.classList.add(
                "selected"
            );

        }}

    }});


    showNodeInformation(node);

}}


// ============================================================
// SHOW INFORMATION
// ============================================================

function showNodeInformation(node) {{

    const panel =
        document.getElementById(
            "nodeInfo"
        );


    let html = "";


    html +=
        '<div class="info-box">';


    html +=
        '<div class="info-row">' +
        '<span class="info-key">' +
        'Node ID: ' +
        '</span>' +
        node.id +
        '</div>';


    html +=
        '<div class="info-row">' +
        '<span class="info-key">' +
        'Type: ' +
        '</span>' +
        node.type +
        '</div>';


    for (
        const [key, value]
        of Object.entries(
            node.information
        )
    ) {{

        if (
            key === "id" ||
            key === "type"
        ) {{
            continue;
        }}


        html +=
            '<div class="info-row">' +
            '<span class="info-key">' +
            escapeHtml(key) +
            ': ' +
            '</span>' +
            escapeHtml(value) +
            '</div>';

    }}


    html +=
        '</div>';


    // Relationships

    const relationships =
        edges.filter(edge =>
            edge.source === node.id ||
            edge.target === node.id
        );


    html +=
        '<h3>Relationships</h3>';


    if (relationships.length === 0) {{

        html +=
            '<p>No relationships found.</p>';

    }} else {{

        relationships
            .slice(0, 50)
            .forEach(edge => {{

                const other =
                    edge.source === node.id
                        ? edge.target
                        : edge.source;


                html +=
                    '<div class="info-box">' +

                    '<div class="info-row">' +

                    '<span class="info-key">' +
                    'Connected To: ' +
                    '</span>' +

                    escapeHtml(other) +

                    '</div>' +

                    '<div class="info-row">' +

                    '<span class="info-key">' +
                    'Relationship: ' +
                    '</span>' +

                    escapeHtml(
                        edge.relationship
                    ) +

                    '</div>' +

                    '</div>';

            }});

    }}


    panel.innerHTML = html;

}}


// ============================================================
// CLEAR SELECTION
// ============================================================

function clearSelection() {{

    document
        .querySelectorAll(".selected")
        .forEach(element => {{

            element.classList.remove(
                "selected"
            );

        }});


    document.getElementById(
        "nodeInfo"
    ).innerHTML =
        "Click a node to see information.";

}}


// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHtml(value) {{

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}}


// ============================================================
// CLICK EMPTY AREA
// ============================================================

svg.addEventListener(
    "click",
    function() {{

        clearSelection();

    }}
);


</script>


</body>

</html>
"""


# ============================================================
# SAVE HTML
# ============================================================

OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)


with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    file.write(html_page)


# ============================================================
# FINISHED
# ============================================================

print()
print("=" * 55)
print("       VISUALIZATION CREATED")
print("=" * 55)

print()
print("Nodes displayed :", len(nodes_data))
print("Edges displayed :", len(edges_data))

print()
print("Edge width      :", EDGE_WIDTH)
print("Edge opacity    :", EDGE_OPACITY)

print()
print("HTML file:")
print(OUTPUT_FILE.resolve())

print()
print("=" * 55)
print("Open the HTML file in your browser.")
print("=" * 55)