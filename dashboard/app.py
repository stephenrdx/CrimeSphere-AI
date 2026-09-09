import streamlit as st
import pandas as pd
import networkx as nx
from pathlib import Path
from itertools import combinations
import html

# ============================================================
# CAPACITY / CRIMINAL NETWORK ANALYSIS — CRIMESPHERE UI
# Dashboard layout intentionally follows the supplied reference:
# narrow dark sidebar + six KPI cards + Recent Cases table.
# ============================================================

st.set_page_config(
    page_title="CrimeSphere AI — Investigation Intelligence",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

FILES = {
    "cdr": DATA_DIR / "cdr_records.csv",
    "transactions": DATA_DIR / "transactions.csv",
    "locations": DATA_DIR / "location_events.csv",
    "case_assoc": DATA_DIR / "case_associations.csv",
    "cases": DATA_DIR / "cases.csv",
    "forensic": DATA_DIR / "forensic_fingerprint_reports.csv",
    "assessment": PROCESSED_DIR / "investigative_assessment.csv",
    "graph": PROCESSED_DIR / "criminal_network.graphml",
}

# ============================================================
# THEME
# ============================================================

LIGHT = {
    # Warm paper / case-file workspace
    "bg": "#F3F1EC",
    "sidebar": "#E8E5DE",
    "sidebar_2": "#F7F5F0",
    "panel": "#FFFFFF",
    "panel_2": "#FAF9F6",
    "border": "#D7D2C8",
    "border_soft": "#E7E3DA",
    "text": "#1D2730",
    "muted": "#68737B",
    "muted_2": "#8A9298",

    # Detective palette: brass, navy, burgundy, evidence blue
    "gold": "#A97812",
    "gold_bright": "#C08A16",
    "blue": "#245A78",
    "green": "#2F6F5E",
    "red": "#8C2F3B",
    "navy": "#243746",
    "burgundy": "#8C2F3B",
    "paper": "#FFFDF8",
}

# LIGHT MODE ONLY — no dark theme branch is used.
# Initialize ALL session-state settings before they are referenced.
st.session_state.theme = "light"

if "sidebar_width" not in st.session_state:
    st.session_state.sidebar_width = 165

if "font_scale" not in st.session_state:
    st.session_state.font_scale = 100

if "content_density" not in st.session_state:
    st.session_state.content_density = "Comfortable"

if "workspace_gap" not in st.session_state:
    st.session_state.workspace_gap = 40

if "sidebar_collapsed" not in st.session_state:
    st.session_state.sidebar_collapsed = False

T = LIGHT

FONT_SCALE = st.session_state.font_scale / 100
SIDEBAR_WIDTH = st.session_state.sidebar_width

FONT_SCALE = st.session_state.font_scale / 100
SIDEBAR_WIDTH = st.session_state.sidebar_width

# ============================================================
# CSS — MATCHES THE SUPPLIED REFERENCE IMAGE
# ============================================================

st.markdown(
    f"""
<style>
/* Local/system fonts only: reliable offline rendering. */
:root {{
    --bg: {T["bg"]};
    --sidebar: {T["sidebar"]};
    --sidebar2: {T["sidebar_2"]};
    --panel: {T["panel"]};
    --panel2: {T["panel_2"]};
    --border: {T["border"]};
    --border-soft: {T["border_soft"]};
    --text: {T["text"]};
    --muted: {T["muted"]};
    --muted2: {T["muted_2"]};
    --gold: {T["gold"]};
    --gold-bright: {T["gold_bright"]};
    --navy: {T["navy"]};
    --burgundy: {T["burgundy"]};
    --paper: {T["paper"]};
    --sidebar-width: {SIDEBAR_WIDTH}px;
    --content-left: {SIDEBAR_WIDTH}px;
    --workspace-gap: 40px;
    --font-scale: {FONT_SCALE};
}}

html, body, [class*="css"], .stApp {{
    font-family: "Segoe UI", "Arial", sans-serif;
}}

.stApp {{
    background: var(--bg);
    color: var(--text);
}}

[data-testid="stHeader"] {{
    background: transparent;
}}

[data-testid="stToolbar"] {{
    display: none;
}}

/* The reference uses a permanent left navigation. We render our own
   sidebar so it cannot disappear because Streamlit's sidebar is collapsed. */
[data-testid="stSidebar"] {{
    display: none !important;
}}

/* Dedicated visual gutter between navigation and workspace. */
.custom-left-sidebar::after {{
    content: "";
    position: absolute;
    top: 0;
    right: calc(-1 * var(--workspace-gap));
    width: var(--workspace-gap);
    height: 100%;
    background: var(--bg);
    border-right: 1px solid var(--border-soft);
    pointer-events: none;
}}

.custom-left-sidebar {{
    position: fixed;
    z-index: 999999;
    left: 0;
    top: 0;
    bottom: 0;
    width: var(--sidebar-width);
    background: var(--sidebar);
    border-right: 1px solid var(--border);
    box-sizing: border-box;
    overflow-y: auto;
}}

.custom-left-sidebar .app-layout-toggle {{
    position: fixed;
    left: calc(var(--sidebar-width) - 14px);
    top: 13px;
    z-index: 1000001;
    width: 28px;
    height: 28px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--panel);
    color: var(--text);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    box-shadow: 0 2px 8px rgba(0,0,0,.22);
}}

.custom-left-sidebar {{
    transition: width .18s ease;
}}

body {{
    font-size: calc(14px * var(--font-scale));
}}


.sidebar-collapsed .custom-left-sidebar {{
    width: 0 !important;
    overflow: hidden !important;
    border-right: 0 !important;
}}

.sidebar-collapsed .app-layout-toggle {{
    left: 12px !important;
}}

.sidebar-collapsed 


/* ============================================================
   LIGHT DETECTIVE / CASE-FILE VISUAL SYSTEM
   ============================================================ */

.stApp {{
    background:
        linear-gradient(rgba(255,255,255,.55), rgba(255,255,255,.55)),
        var(--bg) !important;
}}

/* Paper-like workspace */
[data-testid="stAppViewContainer"] {{
    background: var(--bg) !important;
}}

/* Main page headings */
.page-title {{
    color: var(--navy) !important;
    letter-spacing: -0.02em;
}}

.platform-label {{
    color: var(--muted) !important;
    text-transform: uppercase;
    letter-spacing: .08em;
}}

/* Case-file style cards */
.kpi-card,
.section-card,
.info-card,
.evidence-card {{
    background: var(--paper) !important;
    border-color: var(--border) !important;
    box-shadow: 0 2px 10px rgba(36,55,70,.05) !important;
}}

/* Brass accent instead of generic yellow */
.kpi-value,
.score,
.highlight,
a {{
    color: var(--gold) !important;
}}

button[kind="primary"] {{
    background: var(--burgundy) !important;
    border-color: var(--burgundy) !important;
    color: #ffffff !important;
}}

button[kind="primary"]:hover {{
    background: #742531 !important;
    border-color: #742531 !important;
}}

/* Detective status pills */
.status-low,
.status-medium,
.status-high,
.status-very-high {{
    border-radius: 999px !important;
    font-weight: 700 !important;
}}

/* Data tables resemble evidence registers */
[data-testid="stDataFrame"] {{
    background: var(--paper) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
}}

/* Expanders / evidence sections */
[data-testid="stExpander"] {{
    background: var(--paper) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
}}

[data-testid="stExpander"] summary:hover {{
    color: var(--burgundy) !important;
}}

/* Form controls */
input, textarea, select {{
    background: var(--paper) !important;
    color: var(--text) !important;
    border-color: var(--border) !important;
}}

/* Sidebar: light paper with a navy case-file identity */
.custom-left-sidebar {{
    background: var(--sidebar) !important;
    border-right: 1px solid var(--border) !important;
    box-shadow: 3px 0 14px rgba(29,39,48,.06);
}}

.custom-left-sidebar .brand {{
    background: var(--navy);
    border-bottom: 3px solid var(--gold);
}}

.custom-left-sidebar .brand-name {{
    color: #FFFFFF !important;
}}

.custom-left-sidebar .brand-sub {{
    color: #D9E1E6 !important;
}}

.custom-left-sidebar .nav-section {{
    color: var(--navy) !important;
    font-weight: 800 !important;
    letter-spacing: .14em !important;
}}

.custom-left-sidebar .nav-link {{
    color: #35434D !important;
    border-left-color: transparent !important;
}}

.custom-left-sidebar .nav-link:hover {{
    background: #F6F2E9 !important;
    color: var(--navy) !important;
    border-left-color: var(--gold) !important;
}}

.custom-left-sidebar .nav-link.active {{
    background: #DDD8CE !important;
    color: var(--navy) !important;
    border-left-color: var(--burgundy) !important;
    font-weight: 700 !important;
}}

.custom-left-sidebar .nav-icon {{
    filter: saturate(.75);
}}

.custom-left-sidebar .sidebar-footer {{
    color: #6B746F !important;
    background: rgba(255,255,255,.35);
    border-top: 1px solid var(--border);
}}

/* Clear separation between navigation and work area */
.custom-left-sidebar::after {{
    background: var(--bg) !important;
    border-right: 1px solid var(--border) !important;
}}

/* Section headers have a subtle case-file divider */
.section-title,
.card-title {{
    color: var(--navy) !important;
}}

/* ============================================================
   FINAL WORKSPACE GEOMETRY
   ============================================================ */
:root {{
    --sidebar-width: 165px;
    --workspace-gap: 40px;
    --workspace-left: calc(var(--sidebar-width) + var(--workspace-gap));
}}

.custom-left-sidebar {{
    position: fixed !important;
    z-index: 999999 !important;
    left: 0 !important;
    top: 0 !important;
    bottom: 0 !important;
    width: var(--sidebar-width) !important;
    overflow-y: auto !important;
    box-sizing: border-box !important;
}}

[data-testid="stAppViewContainer"] {{
    width: 100% !important;
    overflow-x: hidden !important;
}}

[data-testid="stAppViewContainer"] .main,
[data-testid="stAppViewContainer"] section.main {{
    width: 100% !important;
    max-width: none !important;
    margin: 0 !important;
    padding: 0 !important;
    box-sizing: border-box !important;
}}

[data-testid="stAppViewContainer"] .main .block-container,
[data-testid="stMainBlockContainer"],
[data-testid="stAppViewContainer"] [data-testid="stMainBlockContainer"] {{
    width: 100% !important;
    max-width: none !important;
    margin: 0 !important;
    box-sizing: border-box !important;
    padding-top: 18px !important;
    padding-right: 22px !important;
    padding-bottom: 42px !important;
    padding-left: calc(var(--workspace-left) + 18px) !important;
}}

[data-testid="stAppViewContainer"] .main .block-container > div,
[data-testid="stMainBlockContainer"] > div {{
    max-width: 100% !important;
    box-sizing: border-box !important;
}}

[data-testid="stDataFrame"],
[data-testid="stTable"],
[data-testid="stPlotlyChart"],
[data-testid="stArrowVegaLiteChart"],
[data-testid="stPydeckChart"] {{
    width: 100% !important;
    max-width: 100% !important;
    box-sizing: border-box !important;
}}

.custom-left-sidebar::after {{
    content: "";
    position: absolute;
    top: 0;
    right: calc(-1 * var(--workspace-gap));
    width: var(--workspace-gap);
    height: 100%;
    background: var(--bg);
    border-right: 1px solid var(--border-soft);
    pointer-events: none;
}}

@media (max-width: 900px) {{
    :root {{
        --sidebar-width: 150px;
        --workspace-gap: 28px;
        --workspace-left: calc(var(--sidebar-width) + var(--workspace-gap));
    }}

    [data-testid="stAppViewContainer"] .main .block-container,
    [data-testid="stMainBlockContainer"],
    [data-testid="stAppViewContainer"] [data-testid="stMainBlockContainer"] {{
        padding-left: calc(var(--workspace-left) + 12px) !important;
        padding-right: 12px !important;
    }}
}}

.brand {{
    height: 61px;
}}

.custom-left-sidebar .nav-section {{
    margin-top: 18px;
}}

.custom-left-sidebar .nav-link {{
    height: 32px;
    box-sizing: border-box;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 12px 0 19px;
    color: #c6cbd2;
    text-decoration: none;
    font-size: 10px;
    border-left: 2px solid transparent;
}}

.custom-left-sidebar .nav-link:hover {{
    background: #1d232b;
    color: #ffffff;
    border-left-color: var(--gold);
}}

.custom-left-sidebar .nav-link.active {{
    background: #222830;
    color: #ffffff;
    border-left-color: var(--gold);
}}

.custom-left-sidebar .nav-icon {{
    width: 13px;
    text-align: center;
    font-size: 11px;
}}

.custom-left-sidebar .sidebar-footer {{
    position: absolute;
    left: 0;
    bottom: 0;
    width: var(--sidebar-width);
}}

/* Workspace sizing: the navigation never sits on top of the main work area. */
/* Reliable workspace geometry.
   Streamlit controls its main column with an internal flex layout, so the
   visual gap is created with padding rather than a fragile margin. */
[data-testid="stAppViewContainer"] .main {{
    width: 100% !important;
    max-width: 100% !important;
    box-sizing: border-box !important;
}}

[data-testid="stAppViewContainer"] 
[data-testid="stAppViewContainer"] .main .block-container > div {{
    max-width: 100% !important;
}}

[data-testid="stDataFrame"] {{
    max-width: 100% !important;
}}

[data-testid="stSidebar"] > div:first-child {{
    padding-top: 0 !important;
    background: var(--sidebar) !important;
}}

[data-testid="stSidebarContent"] {{
    background: var(--sidebar) !important;
}}

[data-testid="stSidebar"] .stButton {{
    display: none !important;
}}

[data-testid="stSidebar"] .stButton > button {{
    width: 100% !important;
    min-height: 32px !important;
    height: 32px !important;
    padding: 0 12px 0 19px !important;
    margin: 0 !important;
    border: 0 !important;
    border-left: 2px solid transparent !important;
    border-radius: 0 !important;
    background: transparent !important;
    box-shadow: none !important;
    color: #c6cbd2 !important;
    text-align: left !important;
    font-size: 10px !important;
    font-weight: 500 !important;
}}

[data-testid="stSidebar"] .stButton > button p {{
    font-size: 10px !important;
    line-height: 12px !important;
}}

[data-testid="stSidebar"] .stButton > button div {{
    justify-content: flex-start !important;
}}

[data-testid="stSidebar"] .stButton > button:hover {{
    background: #1d232b !important;
    color: #ffffff !important;
    border-left-color: var(--gold) !important;
}}

[data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] {{
    display: flex !important;
}}

[data-testid="stSidebar"] * {{
    color: var(--text);
}}

[data-testid="stSidebar"] .block-container {{
    padding: 0 !important;
}}


.brand {{
    height: 61px;
    padding: 15px 15px 10px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--sidebar);
}}

.brand-name {{
    color: var(--gold-bright);
    font-size: 16px;
    line-height: 18px;
    font-weight: 800;
    letter-spacing: -0.3px;
}}

.brand-sub {{
    margin-top: 3px;
    color: var(--muted);
    font-size: 7px;
    line-height: 9px;
    letter-spacing: 1px;
    text-transform: uppercase;
}}

.nav-section {{
    color: var(--muted_2);
    font-size: 7px;
    font-weight: 700;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    margin: 18px 14px 6px 20px;
}}

.nav-item {{
    height: 32px;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 12px 0 19px;
    color: #c6cbd2;
    font-size: 10px;
    border-left: 2px solid transparent;
}}

.nav-item.active {{
    color: #ffffff;
    background: #222830;
    border-left-color: var(--gold);
}}

.nav-icon {{
    width: 13px;
    text-align: center;
    font-size: 11px;
}}

.sidebar-footer {{
    position: fixed;
    left: 0;
    bottom: 0;
    width: 194px;
    min-height: 47px;
    box-sizing: border-box;
    padding: 10px 15px 9px 20px;
    background: var(--sidebar);
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 7px;
    line-height: 10px;
}}

.page-title-row {{
    height: 36px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 18px;
}}

.page-title {{
    font-size: 16px;
    line-height: 21px;
    font-weight: 700;
    color: var(--text);
}}

.relationship-person-card {{
    background: var(--paper);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px 16px;
    margin-bottom: 12px;
    box-shadow: 0 2px 8px rgba(36,55,70,.05);
}}

.relationship-person-name {{
    color: var(--navy);
    font-size: 14px;
    font-weight: 800;
    margin-bottom: 10px;
}}

.relationship-status-row {{
    display: flex;
    flex-wrap: wrap;
    gap: 7px;
    margin-bottom: 10px;
}}

.crime-badge {{
    display: inline-block;
    padding: 5px 9px;
    border-radius: 999px;
    font-size: 9px;
    font-weight: 800;
    letter-spacing: .04em;
    border: 1px solid currentColor;
}}

.crime-green {{
    color: #2F6F5E !important;
    background: #E7F3EE;
}}

.crime-yellow {{
    color: #9A6A00 !important;
    background: #FFF3CF;
}}

.crime-red {{
    color: #8C2F3B !important;
    background: #F8E5E8;
}}

.relationship-score,
.relationship-activity {{
    color: var(--muted);
    font-size: 11px;
    line-height: 1.7;
}}

.relationship-score strong,
.relationship-activity strong {{
    color: var(--text);
}}

.crime-range-legend {{
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    padding: 10px 12px;
    margin: 4px 0 12px;
    background: var(--panel2);
    border: 1px solid var(--border-soft);
    border-radius: 5px;
    color: var(--muted);
    font-size: 9px;
    font-weight: 700;
}}

.legend-dot {{
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 5px;
}}

.legend-dot.green {{ background: #2F6F5E; }}
.legend-dot.yellow {{ background: #D49A14; }}
.legend-dot.red {{ background: #8C2F3B; }}

.case-file-strip {{
    display: flex;
    align-items: center;
    gap: 18px;
    min-height: 34px;
    margin: 0 0 12px 0;
    padding: 0 10px;
    border-left: 3px solid var(--gold);
    border-top: 1px solid var(--border-soft);
    border-bottom: 1px solid var(--border-soft);
    background: rgba(255,253,248,.7);
    color: var(--muted);
    font-size: 9px;
    font-weight: 800;
    letter-spacing: .08em;
    text-transform: uppercase;
}}

.case-badge {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 7px 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--paper);
    color: var(--burgundy);
    font-size: 9px;
    font-weight: 800;
    letter-spacing: .12em;
    white-space: nowrap;
}}

.platform-label {{
    color: #252a31;
    font-size: 8px;
    margin-top: 4px;
}}

.kpi-grid {{
    display: none;
}}

.kpi-card {{
    width: 100%;
    min-height: 70px;
    height: 70px;
    height: 70px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 5px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    box-sizing: border-box;
}}

.kpi-value {{
    color: var(--gold-bright);
    font-size: 23px;
    line-height: 23px;
    font-weight: 800;
}}

.kpi-label {{
    color: var(--muted);
    margin-top: 8px;
    font-size: 7px;
    line-height: 8px;
    letter-spacing: .8px;
    text-transform: uppercase;
    text-align: center;
}}

/* Tables and analysis panels stay inside the workspace instead of
   pushing underneath/behind the navigation. */
div[data-testid="stDataFrame"] {{
    overflow-x: auto !important;
}}

.element-container, .stMarkdown, .stDataFrame, [data-testid="stPlotlyChart"] {{
    max-width: 100% !important;
    box-sizing: border-box !important;
}}

.workspace-gap {{
    height: var(--workspace-gap);
    width: 100%;
}}

.section-card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow: hidden;
}}

.section-header {{
    height: 43px;
    padding: 0 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--panel_2);
    border-bottom: 1px solid var(--border);
    box-sizing: border-box;
}}

.section-title {{
    font-size: 10px;
    font-weight: 700;
    color: var(--text);
}}

.new-case {{
    background: var(--gold-bright);
    color: #111111;
    border-radius: 3px;
    padding: 6px 9px;
    font-size: 8px;
    font-weight: 700;
}}

.case-head {{
    display: grid;
    grid-template-columns: 1.05fr 2fr 1.2fr 2.3fr .9fr 1.05fr;
    min-height: 29px;
    align-items: center;
    background: var(--panel);
    border-bottom: 1px solid var(--border-soft);
}}

.case-head div {{
    padding: 0 6px;
    color: var(--text);
    font-size: 8px;
    font-weight: 700;
}}

.case-row {{
    display: grid;
    grid-template-columns: 1.05fr 2fr 1.2fr 2.3fr .9fr 1.05fr;
    min-height: 55px;
    align-items: center;
    border-bottom: 1px solid var(--border-soft);
}}

.case-row div {{
    padding: 0 6px;
    color: var(--muted);
    font-size: 8px;
}}

.empty-row {{
    height: 54px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #1f252c;
    font-size: 8px;
}}

.empty-row a {{
    color: #3b82f6;
    margin-left: 4px;
}}

.pill {{
    display: inline-block;
    border: 1px solid #3b414a;
    border-radius: 999px;
    padding: 3px 7px;
    font-size: 7px;
}}

.score {{
    color: var(--gold-bright) !important;
    font-weight: 700;
}}

.action-link {{
    color: #3b82f6 !important;
}}

.disclaimer {{
    margin-top: 16px;
    color: var(--muted_2);
    font-size: 8px;
}}

.dashboard-content {{
    width: 100%;
}}

.nav-button-wrap.nav-active .stButton > button {{
    background: #222830 !important;
    color: #ffffff !important;
    border-left-color: var(--gold) !important;
}}

.nav-button-wrap {{
    margin: 0 !important;
    padding: 0 !important;
}}

/* Visible Dashboard Dark/Light Mode toggle */
div[data-testid="column"] button[kind="secondary"] {{
    min-height: 28px;
    height: 28px;
    padding: 0 6px;
    margin-top: 0;
    border: 1px solid var(--border);
    border-radius: 5px;
    background: var(--panel);
    color: var(--text);
    font-size: 13px;
}}

div[data-testid="column"] button[kind="secondary"]:hover {{
    border-color: var(--gold);
    color: var(--gold-bright);
}}

@media (max-width: 1050px) {{
    .kpi-grid {{
        grid-template-columns: repeat(3, minmax(0, 1fr));
    }}
}}

@media (max-width: 700px) {{
    .custom-left-sidebar {{
        width: 180px;
    }}

    .custom-left-sidebar .sidebar-footer {{
        width: 180px;
    }}

    [data-testid="stAppViewContainer"] .main {{
        width: 100% !important;
        margin-left: 0 !important;
    }}

    [data-testid="stAppViewContainer"] </style>
""",
    unsafe_allow_html=True,
)

# ============================================================
# DATA LOADING
# ============================================================

@st.cache_data(show_spinner=False)
def read_csv(path: Path) -> pd.DataFrame:
    try:
        if path.exists():
            return pd.read_csv(path)
    except Exception:
        pass
    return pd.DataFrame()

@st.cache_resource(show_spinner=False)
def read_graph(path: Path):
    try:
        if path.exists():
            graph = nx.read_graphml(path)
            return nx.Graph(graph) if graph.is_directed() else graph
    except Exception:
        pass
    return nx.Graph()

cdr = read_csv(FILES["cdr"])
transactions = read_csv(FILES["transactions"])
locations = read_csv(FILES["locations"])
case_assoc = read_csv(FILES["case_assoc"])
cases = read_csv(FILES["cases"])
forensic = read_csv(FILES["forensic"])
assessment = read_csv(FILES["assessment"])
G = read_graph(FILES["graph"])

def clean_id_columns(df):
    if df.empty:
        return df
    df = df.copy()
    for c in df.columns:
        if c.endswith("_id"):
            df[c] = df[c].astype(str).str.strip()
    return df

cdr = clean_id_columns(cdr)
transactions = clean_id_columns(transactions)
locations = clean_id_columns(locations)
case_assoc = clean_id_columns(case_assoc)
cases = clean_id_columns(cases)
forensic = clean_id_columns(forensic)
assessment = clean_id_columns(assessment)

# ============================================================
# DERIVED METRICS
# ============================================================

def person_ids():
    ids = set()

    if "person_id" in assessment.columns:
        ids.update(assessment["person_id"].dropna().astype(str))

    for df, cols in [
        (cdr, ["caller_person_id", "receiver_person_id"]),
        (transactions, ["sender_person_id", "receiver_person_id"]),
        (locations, ["person_id"]),
        (case_assoc, ["person_id"]),
        (forensic, ["person_id"]),
    ]:
        for col in cols:
            if col in df.columns:
                ids.update(df[col].dropna().astype(str))

    # Graph fallback
    for node, attrs in G.nodes(data=True):
        node_type = str(
            attrs.get("type", attrs.get("node_type", attrs.get("entity_type", "")))
        ).lower()
        if node_type in {"person", "criminal"} or str(node).startswith("P"):
            ids.add(str(node))

    return sorted(x for x in ids if x and x.lower() != "nan")

persons = person_ids()

def unique_count(df, columns):
    for col in columns:
        if col in df.columns:
            return int(df[col].dropna().astype(str).nunique())
    return 0

criminal_pairs = set()

def add_direct_pairs(df, a_col, b_col):
    if df.empty or a_col not in df.columns or b_col not in df.columns:
        return
    valid = set(persons)
    for _, row in df[[a_col, b_col]].dropna().iterrows():
        a, b = str(row[a_col]), str(row[b_col])
        if a != b and a in valid and b in valid:
            criminal_pairs.add(tuple(sorted((a, b))))

add_direct_pairs(cdr, "caller_person_id", "receiver_person_id")
add_direct_pairs(transactions, "sender_person_id", "receiver_person_id")

if {"person_id", "location_id"}.issubset(locations.columns):
    for _, group in locations.groupby("location_id"):
        people = sorted(set(group["person_id"].astype(str)) & set(persons))
        criminal_pairs.update(combinations(people, 2))

if {"person_id", "case_id"}.issubset(case_assoc.columns):
    for _, group in case_assoc.groupby("case_id"):
        people = sorted(set(group["person_id"].astype(str)) & set(persons))
        criminal_pairs.update(combinations(people, 2))

total_criminals = len(persons)

case_ids = set()
for df in [cases, case_assoc, forensic]:
    if "case_id" in df.columns:
        case_ids.update(df["case_id"].dropna().astype(str))
total_cases = len(case_ids)

graph_relationships = int(G.number_of_edges())
criminal_relationships = len(criminal_pairs)
total_relationships = graph_relationships + criminal_relationships

high_relevance = 0
if not assessment.empty and "person_id" in assessment.columns:
    score_col = next(
        (c for c in ["investigative_score", "score", "overall_score"] if c in assessment.columns),
        None,
    )
    if score_col:
        high_relevance = int(
            pd.to_numeric(assessment[score_col], errors="coerce").fillna(0).ge(61).sum()
        )

key_network_nodes = int(G.number_of_nodes())

# ============================================================
# PERMANENT LEFT SIDEBAR
# ============================================================

if "page" not in st.session_state:
    st.session_state.page = "Dashboard"

NAV = [
    ("MAIN", [
        ("🕵️", "Dashboard"),
        ("📂", "Cases"),
    ]),
    ("INTELLIGENCE", [
        ("📄", "FIR Intelligence"),
        ("🗂", "Historical Cases"),
        ("📞", "CDR Intelligence"),
        ("💰", "Transactions"),
        ("◉", "Surveillance"),
    ]),
    ("ANALYSIS", [
        ("👤", "Individual Investigation"),
        ("🌐", "Network Explorer"),
        ("🔗", "Relationships"),
        ("▦", "Timeline"),
        ("🔬", "Evidence"),
    ]),
    ("SYSTEM", [
        ("📊", "Reports"),
        ("⚙", "Settings"),
    ]),
]

valid_pages = [label for _, items in NAV for _, label in items]

# Allow the HTML navigation links to control the Streamlit page.
try:
    requested_page = st.query_params.get("page")
except Exception:
    requested_page = None

if requested_page in valid_pages:
    st.session_state.page = requested_page

if st.session_state.sidebar_collapsed:
    st.markdown(
        '<style>:root {{ --sidebar-width: 0px; --workspace-gap: 0px; --workspace-left: 0px; }}</style>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        f'<style>:root {{ --sidebar-width: {SIDEBAR_WIDTH}px; --workspace-gap: {st.session_state.workspace_gap}px; --workspace-left: calc({SIDEBAR_WIDTH}px + {st.session_state.workspace_gap}px); }}</style>',
        unsafe_allow_html=True,
    )

toggle_label = "›" if st.session_state.sidebar_collapsed else "‹"
toggle_help = "Show navigation" if st.session_state.sidebar_collapsed else "Hide navigation"

if st.button(toggle_label, key="layout_sidebar_toggle", help=toggle_help):
    st.session_state.sidebar_collapsed = not st.session_state.sidebar_collapsed
    st.rerun()

sidebar_html = """
<div class="custom-left-sidebar">
    <div class="brand">
        <div class="brand-name">CrimeSphere AI</div>
        <div class="brand-sub">Investigation Intelligence</div>
    </div>
"""

for section, items in NAV:
    sidebar_html += f'<div class="nav-section">{html.escape(section)}</div>'
    for icon, label in items:
        active = " active" if st.session_state.page == label else ""
        sidebar_html += (
            f'<a class="nav-link{active}" href="?page={html.escape(label)}">'
            f'<span class="nav-icon">{icon}</span>'
            f'<span>{html.escape(label)}</span>'
            f'</a>'
        )

sidebar_html += """
    <div class="sidebar-footer">
        Scores = Investigative Relevance.<br>
        NOT probability of guilt.
    </div>
</div>
"""

st.markdown(sidebar_html, unsafe_allow_html=True)

# ============================================================
# GENERIC HELPERS FOR OTHER NAVIGATION PAGES
# ============================================================

def safe_date_column(df, candidates):
    for col in candidates:
        if col in df.columns:
            return col
    return None

def score_for_person(person):
    if assessment.empty or "person_id" not in assessment.columns:
        return 0.0
    row = assessment[assessment["person_id"].astype(str) == str(person)]
    if row.empty:
        return 0.0
    for col in ["investigative_score", "score", "overall_score"]:
        if col in row.columns:
            return float(pd.to_numeric(row.iloc[0][col], errors="coerce") or 0)
    return 0.0

def score_range(score):
    if score <= 30:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    if score <= 80:
        return "HIGH"
    return "VERY HIGH"


def crime_range_class(score):
    """Map the investigative score to the requested green/yellow/red range."""
    if score <= 30:
        return "crime-green"
    if score <= 60:
        return "crime-yellow"
    return "crime-red"


def activity_count_for_person(person):
    """Count available activity/evidence records associated with a person."""
    pid = str(person)
    total = 0

    if {"caller_person_id", "receiver_person_id"}.issubset(cdr.columns):
        total += int(
            (
                cdr["caller_person_id"].astype(str).eq(pid)
                | cdr["receiver_person_id"].astype(str).eq(pid)
            ).sum()
        )

    if {"sender_person_id", "receiver_person_id"}.issubset(transactions.columns):
        total += int(
            (
                transactions["sender_person_id"].astype(str).eq(pid)
                | transactions["receiver_person_id"].astype(str).eq(pid)
            ).sum()
        )

    if "person_id" in locations.columns:
        total += int(locations["person_id"].astype(str).eq(pid).sum())

    if "person_id" in case_assoc.columns:
        total += int(case_assoc["person_id"].astype(str).eq(pid).sum())

    if "person_id" in forensic.columns:
        total += int(forensic["person_id"].astype(str).eq(pid).sum())

    return total


def frequent_activity_status(activity_count):
    """Classify activity frequency using the available project evidence volume."""
    if activity_count >= 10:
        return "FREQUENT ACTIVITY", "crime-red"
    if activity_count >= 5:
        return "REPEATED ACTIVITY", "crime-yellow"
    return "LOW ACTIVITY", "crime-green"

# ============================================================
# DASHBOARD — REFERENCE IMAGE OUTPUT
# ============================================================

def render_dashboard():
    st.markdown(
        """
        <div class="page-title-row">
            <div>
                <div class="page-title">Investigation Dashboard</div>
                <div class="platform-label">CrimeSphere AI · Case Intelligence & Evidence Analysis</div>
            </div>
            <div class="case-badge">CASE INTELLIGENCE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cards = [
        ("0" if total_cases == 0 else str(total_cases), "ACTIVE CASES"),
        ("0" if total_cases == 0 else str(total_cases), "HISTORICAL FIRS"),
        (str(total_criminals), "PERSONS IDENTIFIED"),
        (str(total_relationships), "RELATIONSHIPS"),
        (str(high_relevance), "HIGH-RELEVANCE"),
        (str(key_network_nodes), "KEY NETWORK NODES"),
    ]

    st.markdown(
        """
        <div class="case-file-strip">
            <span>🔎 INVESTIGATION CONTROL</span>
            <span>CASE DATA</span>
            <span>RELATIONSHIP INTELLIGENCE</span>
            <span>EVIDENCE REGISTER</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    kpi_cols = st.columns(6, gap="small")
    for col, (value, label) in zip(kpi_cols, cards):
        with col:
            st.markdown(
                f"""
                <div class="kpi-card">
                    <div class="kpi-value">{html.escape(value)}</div>
                    <div class="kpi-label">{html.escape(label)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown(
        """
        <div class="section-card">
            <div class="section-header">
                <div class="section-title">Recent Cases</div>
                <div class="new-case">+ New Case</div>
            </div>
        """,
        unsafe_allow_html=True,
    )

    headers = ["Case ID", "Title", "Status", "Primary Person", "Score", "Actions"]
    st.markdown(
        '<div class="case-head">' + "".join(
            f"<div>{h}</div>" for h in headers
        ) + "</div>",
        unsafe_allow_html=True,
    )

    if cases.empty:
        st.markdown(
            '<div class="empty-row">No cases found <a href="#">Create one.</a></div>',
            unsafe_allow_html=True,
        )
    else:
        recent = cases.copy().head(12)

        # Attach a primary person where case associations exist.
        primary = {}
        if {"case_id", "person_id"}.issubset(case_assoc.columns):
            for case_id, grp in case_assoc.groupby("case_id"):
                if not grp.empty:
                    primary[str(case_id)] = str(grp.iloc[0]["person_id"])

        for _, row in recent.iterrows():
            case_id = str(row.get("case_id", "N/A"))
            title = str(row.get("crime_type", row.get("title", "Investigation")))
            person = primary.get(case_id, "—")
            score = score_for_person(person) if person != "—" else 0
            status = score_range(score) if person != "—" else "OPEN"

            st.markdown(
                f"""
                <div class="case-row">
                    <div>{html.escape(case_id)}</div>
                    <div>{html.escape(title)}</div>
                    <div><span class="pill">{html.escape(status)}</span></div>
                    <div>{html.escape(person)}</div>
                    <div class="score">{score:.1f}</div>
                    <div class="action-link">View</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        """
        <div class="disclaimer">
            Scores = Investigative Relevance. NOT probability of guilt. Analytical associations are investigative aids and are not legal determinations.
        </div>
        """,
        unsafe_allow_html=True,
    )

# ============================================================
# CASES
# ============================================================

def render_cases():
    st.markdown(
        '<div class="page-title-row"><div class="page-title">Cases</div></div>',
        unsafe_allow_html=True,
    )
    if cases.empty:
        st.info("No case dataset was found.")
    else:
        st.dataframe(cases, use_container_width=True, hide_index=True)

# ============================================================
# INTELLIGENCE TABLES
# ============================================================

def render_table_page(title, df):
    st.markdown(
        f'<div class="page-title-row"><div class="page-title">{html.escape(title)}</div></div>',
        unsafe_allow_html=True,
    )
    if df.empty:
        st.info(f"No data available for {title}.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

# ============================================================
# NETWORK EXPLORER
# ============================================================

def render_network():
    st.markdown(
        '<div class="page-title-row"><div class="page-title">Network Explorer</div></div>',
        unsafe_allow_html=True,
    )

    if G.number_of_nodes() == 0:
        st.info("No GraphML network is available.")
        return

    st.metric("Network Nodes", G.number_of_nodes())
    st.metric("Network Edges", G.number_of_edges())

    nodes = list(G.nodes())
    selected = st.selectbox("Focus node", nodes)

    neighbors = list(G.neighbors(selected))
    st.write(f"Connections for **{selected}**: {len(neighbors)}")

    if neighbors:
        rows = []
        for n in neighbors:
            rows.append({
                "Node": str(n),
                "Relationship": str(G.edges[selected, n].get("relationship", "Relationship")),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ============================================================
# RELATIONSHIP ANALYSIS
# ============================================================

def render_relationship_graph(person_a, person_b, score_a, score_b, activity_a, activity_b):
    """Render the Relationships crime-range comparison graph."""
    graph_df = pd.DataFrame({
        "Criminal": [str(person_a), str(person_b)],
        "Crime Score": [float(score_a), float(score_b)],
        "Activity / Evidence Records": [int(activity_a), int(activity_b)],
    }).set_index("Criminal")

    st.markdown("### Crime Range Comparison Graph")
    st.caption(
        "Visual comparison of the existing investigative scores and available activity/evidence records. "
        "Scores are indicators only and do not establish guilt."
    )

    # Streamlit's native chart keeps the graph dependency-free and responsive.
    st.bar_chart(
        graph_df[["Crime Score"]],
        y_label="Investigative Score (0–100)",
        x_label="Selected criminal",
        y=["Crime Score"],
        height=360,
    )

    # Explicit range legend beneath the graph.
    st.markdown(
        """
        <div class="crime-range-legend">
            <span><b class="legend-dot green"></b> LOW · 0–30</span>
            <span><b class="legend-dot yellow"></b> MEDIUM · 31–60</span>
            <span><b class="legend-dot red"></b> HIGH / VERY HIGH · 61–100</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    activity_df = pd.DataFrame({
        "Criminal": [str(person_a), str(person_b)],
        "Available Records": [int(activity_a), int(activity_b)],
    }).set_index("Criminal")

    st.markdown("### Activity Frequency Graph")
    st.bar_chart(
        activity_df,
        y_label="Available activity/evidence records",
        x_label="Selected criminal",
        y=["Available Records"],
        height=300,
    )


def render_relationships():
    st.markdown(
        '<div class="page-title-row"><div class="page-title">Relationships</div></div>',
        unsafe_allow_html=True,
    )

    if len(persons) < 2:
        st.info("At least two person IDs are required.")
        return

    a = st.selectbox("Person A", persons, key="rel_a")
    b_options = [p for p in persons if p != a] or persons
    b = st.selectbox("Person B", b_options, key="rel_b")

    evidence = []

    if {"caller_person_id", "receiver_person_id"}.issubset(cdr.columns):
        mask = (
            ((cdr["caller_person_id"].astype(str) == a) & (cdr["receiver_person_id"].astype(str) == b))
            | ((cdr["caller_person_id"].astype(str) == b) & (cdr["receiver_person_id"].astype(str) == a))
        )
        evidence.append(("Phone / CDR", int(mask.sum())))

    if {"sender_person_id", "receiver_person_id"}.issubset(transactions.columns):
        mask = (
            ((transactions["sender_person_id"].astype(str) == a) & (transactions["receiver_person_id"].astype(str) == b))
            | ((transactions["sender_person_id"].astype(str) == b) & (transactions["receiver_person_id"].astype(str) == a))
        )
        evidence.append(("Financial", int(mask.sum())))

    if {"person_id", "location_id"}.issubset(locations.columns):
        la = set(locations.loc[locations["person_id"].astype(str) == a, "location_id"].astype(str))
        lb = set(locations.loc[locations["person_id"].astype(str) == b, "location_id"].astype(str))
        evidence.append(("Common Locations", len(la & lb)))

    if {"person_id", "case_id"}.issubset(case_assoc.columns):
        ca = set(case_assoc.loc[case_assoc["person_id"].astype(str) == a, "case_id"].astype(str))
        cb = set(case_assoc.loc[case_assoc["person_id"].astype(str) == b, "case_id"].astype(str))
        evidence.append(("Common Cases", len(ca & cb)))

    cols = st.columns(len(evidence))
    for col, (label, value) in zip(cols, evidence):
        col.metric(label, value)

    # Criminal range + activity status for both people in the relationship.
    score_a = score_for_person(a)
    score_b = score_for_person(b)
    activity_a = activity_count_for_person(a)
    activity_b = activity_count_for_person(b)
    activity_status_a, activity_class_a = frequent_activity_status(activity_a)
    activity_status_b, activity_class_b = frequent_activity_status(activity_b)

    # ============================================================
    # RELATIONSHIP GRAPHS
    # ============================================================
    render_relationship_graph(
        a, b, score_a, score_b, activity_a, activity_b
    )

    st.markdown("### Criminal Range & Activity Status")

    person_cols = st.columns(2)
    for col, person, score, activity_count, activity_status, activity_class in [
        (person_cols[0], a, score_a, activity_a, activity_status_a, activity_class_a),
        (person_cols[1], b, score_b, activity_b, activity_status_b, activity_class_b),
    ]:
        range_name = score_range(score)
        range_class = crime_range_class(score)
        col.markdown(
            f"""
            <div class="relationship-person-card">
                <div class="relationship-person-name">{html.escape(str(person))}</div>
                <div class="relationship-status-row">
                    <span class="crime-badge {range_class}">
                        CRIME RANGE: {html.escape(range_name)}
                    </span>
                    <span class="crime-badge {activity_class}">
                        {html.escape(activity_status)}
                    </span>
                </div>
                <div class="relationship-score">
                    Investigative Score: <strong>{score:.1f}/100</strong>
                </div>
                <div class="relationship-activity">
                    Available activity/evidence records: <strong>{activity_count}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        """
        <div class="crime-range-legend">
            <span><b class="legend-dot green"></b> LOW (0–30) · Green</span>
            <span><b class="legend-dot yellow"></b> MEDIUM (31–60) · Yellow</span>
            <span><b class="legend-dot red"></b> HIGH / VERY HIGH (61–100) · Red</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption(
        "Frequent Activity is based on the volume of available CDR, transaction, "
        "location, case-association and forensic records for the selected person. "
        "These are investigative indicators, not proof of guilt."
    )

# ============================================================
# EVIDENCE
# ============================================================

def render_evidence():
    st.markdown(
        '<div class="page-title-row"><div class="page-title">Evidence</div></div>',
        unsafe_allow_html=True,
    )

    datasets = [
        ("Forensic Fingerprint Evidence", forensic),
        ("CDR Evidence", cdr),
        ("Transaction Evidence", transactions),
        ("Location Evidence", locations),
        ("Case Associations", case_assoc),
    ]

    for title, df in datasets:
        with st.expander(title, expanded=False):
            if df.empty:
                st.info("No records available.")
            else:
                st.dataframe(df, use_container_width=True, hide_index=True)

# ============================================================
# SETTINGS
# ============================================================

def render_settings():
    st.markdown(
        '<div class="page-title-row"><div class="page-title">Settings</div></div>',
        unsafe_allow_html=True,
    )

    st.markdown("### Project Features")

    st.caption(
        "The redesign changes the visual presentation only. "
        "The original project feature names are preserved."
    )

    feature_groups = {
        "MAIN": ["Dashboard", "Cases"],
        "INTELLIGENCE": [
            "FIR Intelligence",
            "Historical Cases",
            "CDR Intelligence",
            "Transactions",
            "Surveillance",
        ],
        "ANALYSIS": [
            "Network Explorer",
            "Relationships",
            "Timeline",
            "Evidence",
        ],
        "SYSTEM": ["Reports", "Settings"],
    }

    for group, features in feature_groups.items():
        st.markdown(f"**{group}**")
        st.write(" · ".join(features))

    st.markdown("### Investigation Controls")

    st.caption(
        "Original investigation-control names retained: "
        "Search individual, Individual investigation, Open Individual, "
        "Random Individual, Person A search, Person A, Person B search, Person B."
    )


    st.markdown("### Appearance")

    st.success(
        "Light mode is fixed for this application. "
        "The interface uses a clean case-file / detective visual system."
    )

    st.markdown("### Layout")

    sidebar_mode = st.radio(
        "Navigation display",
        ["Compact", "Full", "Hidden"],
        index=(
            2 if st.session_state.sidebar_collapsed
            else 0 if st.session_state.sidebar_width <= 180
            else 1
        ),
        horizontal=True,
        help="Compact keeps the feature names visible while giving the workspace more room.",
    )

    if sidebar_mode == "Hidden":
        st.session_state.sidebar_collapsed = True
        sidebar_width = 0
    else:
        st.session_state.sidebar_collapsed = False
        if sidebar_mode == "Compact":
            sidebar_width = st.slider(
                "Navigation width",
                min_value=150,
                max_value=190,
                value=min(max(int(st.session_state.sidebar_width), 150), 190),
                step=5,
                help="Compact navigation width. This leaves maximum space for investigation details.",
            )
        else:
            sidebar_width = st.slider(
                "Navigation width",
                min_value=190,
                max_value=250,
                value=min(max(int(st.session_state.sidebar_width), 190), 250),
                step=5,
                help="Wider navigation for larger screens.",
            )

    font_scale = st.slider(
        "Text size",
        min_value=80,
        max_value=130,
        value=int(st.session_state.font_scale),
        step=5,
        help="Increase or decrease application text size.",
    )

    workspace_gap = st.slider(
        "Space between navigation and workspace",
        min_value=0,
        max_value=60,
        value=int(st.session_state.workspace_gap),
        step=2,
        help="Increase this value to create more visual separation between the sidebar and your investigation workspace.",
    )

    density = st.radio(
        "Workspace density",
        ["Compact", "Comfortable", "Spacious"],
        index=["Compact", "Comfortable", "Spacious"].index(
            st.session_state.content_density
        ),
        horizontal=True,
    )

    if density == "Compact":
        density_css = "8px 18px 28px 22px"
    elif density == "Spacious":
        density_css = "26px 34px 60px 34px"
    else:
        density_css = "18px 26px 42px 26px"

    if (
        sidebar_width != st.session_state.sidebar_width
        or font_scale != st.session_state.font_scale
        or density != st.session_state.content_density
        or workspace_gap != st.session_state.workspace_gap
    ):
        st.session_state.sidebar_width = sidebar_width
        st.session_state.font_scale = font_scale
        st.session_state.content_density = density
        st.session_state.workspace_gap = workspace_gap
        st.markdown(
            f"""
            <style>
            :root {{
                --sidebar-width: {0 if st.session_state.sidebar_collapsed else sidebar_width}px;
                --workspace-gap: {0 if st.session_state.sidebar_collapsed else workspace_gap}px;
                --workspace-left: calc({0 if st.session_state.sidebar_collapsed else sidebar_width}px + {0 if st.session_state.sidebar_collapsed else workspace_gap}px);
                --font-scale: {font_scale / 100};
            }}
            .main .block-container {{
                padding: {density_css} !important;
            }}
            </style>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### Preview")
    st.caption(
        "Use Navigation display to keep the original feature names visible without "
        "letting the sidebar interrupt the main workspace. Compact is recommended for "
        "laptops. Use Text size and Workspace density to control readability and spacing."
    )

    st.info(
        "Recommended for your laptop: Compact navigation at 160–175 px, "
        "gap 35–45 px, Text size 95–105%, Workspace density Comfortable."
    )

# ============================================================
# INDIVIDUAL INVESTIGATION
# ============================================================

def render_individual_investigation():
    st.markdown(
        '<div class="page-title-row"><div class="page-title">Individual Investigation</div></div>',
        unsafe_allow_html=True,
    )

    if not persons:
        st.info("No person/criminal records are available.")
        return

    selected = st.selectbox(
        "Individual investigation",
        persons,
        key="individual_investigation_select",
    )

    score = score_for_person(selected)
    status = score_range(score)

    connected = set()
    if selected in G:
        connected.update(str(x) for x in G.neighbors(selected))

    if {"caller_person_id", "receiver_person_id"}.issubset(cdr.columns):
        connected.update(
            cdr.loc[
                cdr["caller_person_id"].astype(str).eq(selected),
                "receiver_person_id",
            ].dropna().astype(str)
        )
        connected.update(
            cdr.loc[
                cdr["receiver_person_id"].astype(str).eq(selected),
                "caller_person_id",
            ].dropna().astype(str)
        )

    if {"sender_person_id", "receiver_person_id"}.issubset(transactions.columns):
        connected.update(
            transactions.loc[
                transactions["sender_person_id"].astype(str).eq(selected),
                "receiver_person_id",
            ].dropna().astype(str)
        )
        connected.update(
            transactions.loc[
                transactions["receiver_person_id"].astype(str).eq(selected),
                "sender_person_id",
            ].dropna().astype(str)
        )

    st.markdown("### INDIVIDUAL INVESTIGATION")

    cols = st.columns(4)
    cols[0].metric("Investigative Score", f"{score:.1f} / 100")
    cols[1].metric("Criminal Status / Range", status)
    cols[2].metric("Screening Assessment", "YES" if score > 0 else "NO")
    cols[3].metric("Connected Persons", len(connected))

    st.markdown("### EVIDENCE ANALYSIS")

    evidence_blocks = [
        ("📍 Common Locations", locations),
        ("📅 Common Date & Time", locations),
        ("📁 Common Cases", case_assoc),
        ("📞 Phone Connections", cdr),
        ("🚗 Vehicle Connections", pd.DataFrame()),
        ("🏦 Bank Account Connections", pd.DataFrame()),
        ("💻 Device Connections", pd.DataFrame()),
        ("🧬 Forensic Fingerprint Evidence", forensic),
        ("🔬 Other Available Evidence", pd.DataFrame()),
    ]

    for title, df in evidence_blocks:
        with st.expander(title, expanded=False):
            if df.empty:
                st.caption("No source records available for this evidence category.")
            elif "person_id" in df.columns:
                subset = df[df["person_id"].astype(str).eq(selected)]
                st.dataframe(
                    subset if not subset.empty else df.head(20),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.dataframe(df.head(20), use_container_width=True, hide_index=True)

    st.caption(
        "Analytical scores and relationships are investigative associations only. "
        "They are NOT proof of guilt and NOT legal determinations."
    )

# ROUTER
# ============================================================

page = st.session_state.page

if page == "Dashboard":
    render_dashboard()
elif page == "Individual Investigation":
    render_individual_investigation()
elif page == "Cases":
    render_cases()
elif page == "FIR Intelligence":
    render_table_page("FIR Intelligence", cases)
elif page == "Historical Cases":
    render_table_page("Historical Cases", cases)
elif page == "CDR Intelligence":
    render_table_page("CDR Intelligence", cdr)
elif page == "Transactions":
    render_table_page("Transactions", transactions)
elif page == "Surveillance":
    render_table_page("Surveillance", locations)
elif page == "Network Explorer":
    render_network()
elif page == "Relationships":
    render_relationships()
elif page == "Timeline":
    render_table_page("Timeline", locations)
elif page == "Evidence":
    render_evidence()
elif page == "Reports":
    render_table_page("Reports", assessment)
elif page == "Settings":
    render_settings()
else:
    render_dashboard()
