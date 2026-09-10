import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import networkx as nx
from pathlib import Path
from itertools import combinations
import html
import os
import json
import hashlib
import re
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt
import textwrap
import base64
import hmac
import secrets
import time
import sqlite3
from urllib.parse import quote

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

APP_DIR = Path(__file__).resolve().parent
# Supports both the original dashboard/app.py structure and root-level app.py.
BASE_DIR = APP_DIR.parent if (APP_DIR.parent / "data").exists() else APP_DIR
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
    # Master/entity datasets used by the Network Explorer investigation graph.
    "persons_master": DATA_DIR / "persons.csv",
    "phones": DATA_DIR / "phones.csv",
    "vehicles": DATA_DIR / "vehicles.csv",
    "vehicle_events": DATA_DIR / "vehicle_events.csv",
    "bank_accounts": DATA_DIR / "bank_accounts.csv",
    "devices": DATA_DIR / "devices.csv",
    "surveillance": DATA_DIR / "surveillance_events.csv",
    "locations_master": DATA_DIR / "locations.csv",
    "organizations": DATA_DIR / "organizations.csv",
    # Fingerprint image evidence registry and storage.
    "fingerprint_registry": DATA_DIR / "fingerprint_image_registry.csv",
    "fingerprint_images_dir": DATA_DIR / "fingerprint_images",
}

# ============================================================
# ROLE-BASED AUTHENTICATION
# Category A = Admin (full access)
# Category B = Police / Investigator (operational access)
# ============================================================

USERS_FILE = PROCESSED_DIR / "user_accounts.json"

ROLE_PAGES = {
    "Admin": [label for _, items in [
        ("MAIN", [("", "Dashboard"), ("", "Cases")]),
        ("INTELLIGENCE", [("", "FIR Intelligence"), ("", "Historical Cases"), ("", "CDR Intelligence"), ("", "Transactions"), ("", "Surveillance")]),
        ("ANALYSIS", [("", "Individual Investigation"), ("", "Network Explorer"), ("", "Relationships"), ("", "Timeline"), ("", "Evidence")]),
        ("SYSTEM", [("", "Reports"), ("", "Complaint Box"), ("", "Settings")]),
    ] for _, label in items],
    "Police": [
        "Dashboard", "Cases", "FIR Intelligence", "Historical Cases",
        "CDR Intelligence", "Transactions", "Surveillance",
        "Individual Investigation", "Network Explorer", "Relationships",
        "Timeline", "Evidence", "Reports", "Help & Support"
    ],
    "Investigator": [
        "Dashboard", "Cases", "FIR Intelligence", "Historical Cases",
        "CDR Intelligence", "Transactions", "Surveillance",
        "Individual Investigation", "Network Explorer", "Relationships",
        "Timeline", "Evidence", "Reports", "Help & Support"
    ],
}

ROLE_CATEGORY = {"Admin": "A", "Police": "B", "Investigator": "B"}
ROLE_LABEL = {
    "Admin": "Category A — Administrator",
    "Police": "Category B — Police Officer",
    "Investigator": "Category B — Investigator",
}

def _password_hash(password):
    return hashlib.sha256(str(password).encode("utf-8")).hexdigest()

def _auth_secret():
    """Return a persistent local signing secret for browser session tokens."""
    secret_file = PROCESSED_DIR / ".auth_secret"
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    if secret_file.exists():
        value = secret_file.read_text(encoding="utf-8").strip()
        if value:
            return value.encode("utf-8")
    value = secrets.token_urlsafe(48)
    secret_file.write_text(value, encoding="utf-8")
    return value.encode("utf-8")

def _make_auth_token(username, role, password_hash, ttl_seconds=12 * 60 * 60):
    payload = {
        "u": username,
        "r": role,
        "p": password_hash,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(_auth_secret(), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"

def _restore_auth_from_token(token):
    """Restore authentication after a browser navigation/reconnect."""
    if not token or "." not in token:
        return False
    try:
        body, signature = token.rsplit(".", 1)
        expected = hmac.new(_auth_secret(), body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return False
        username = str(payload.get("u", "")).strip().lower()
        role = str(payload.get("r", ""))
        users = load_users()
        record = users.get(username)
        if not record or not record.get("active", True):
            return False
        if record.get("role") != role or record.get("password_hash") != payload.get("p"):
            return False
        if role not in ROLE_PAGES:
            return False
        st.session_state.authenticated = True
        st.session_state.username = username
        st.session_state.role = role
        st.session_state.category = ROLE_CATEGORY[role]
        st.session_state.auth_token = token
        return True
    except Exception:
        return False

def _default_users():
    # Official CrimeSphere demo accounts. Passwords are stored as SHA-256 hashes,
    # not in plaintext. These replace all previous/legacy login accounts.
    return {
        "kavya": {"user_id": "USR-KAVYA", "full_name": "Kavya", "email": "kavya@crimesphere.ai", "password_hash": _password_hash("Kavya@0512"), "role": "Admin", "active": True, "built_in": True},
        "stephen": {"user_id": "USR-STEPHEN", "full_name": "Stephen", "email": "stephen@crimesphere.ai", "password_hash": _password_hash("Stephen@0512"), "role": "Admin", "active": True, "built_in": True},
        "suhaib": {"user_id": "USR-SUHAIB", "full_name": "Suhaib", "email": "suhaib@crimesphere.ai", "password_hash": _password_hash("Suhaib@2026"), "role": "Police", "active": True, "built_in": True},
        "sameera": {"user_id": "USR-SAMEERA", "full_name": "Sameera", "email": "sameera@crimesphere.ai", "password_hash": _password_hash("Sameera@2026"), "role": "Police", "active": True, "built_in": True},
        "lavanya": {"user_id": "USR-LAVANYA", "full_name": "Lavanya", "email": "lavanya@crimesphere.ai", "password_hash": _password_hash("Lavanya@2026"), "role": "Investigator", "active": True, "built_in": True},
        "vasu": {"user_id": "USR-VASU", "full_name": "Vasu", "email": "vasu@crimesphere.ai", "password_hash": _password_hash("Vasu@2026"), "role": "Investigator", "active": True, "built_in": True},
    }

def load_users():
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not USERS_FILE.exists():
        data = _default_users()
        USERS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data
    try:
        data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and data else _default_users()
    except Exception:
        return _default_users()

def save_users(users):
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")

def _logout():
    for key in list(st.session_state.keys()):
        st.session_state.pop(key, None)
    st.session_state.authenticated = False
    try:
        st.query_params.clear()
    except Exception:
        pass
    st.rerun()
    
def render_login():
    st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] .main .block-container {
        max-width: 560px !important; margin: 0 auto !important; padding-top: 9vh !important;
    }
    .login-card { background:#fff; border:1px solid #d7d2c8; border-radius:14px; padding:38px 42px; box-shadow:0 18px 50px rgba(25,35,45,.10); }
    .login-brand { font-size:30px; font-weight:800; color:#243746; letter-spacing:-1px; }
    .login-sub { color:#68737b; margin:4px 0 24px; font-size:13px; }
    .login-role { display:inline-block; background:#f3f1ec; border:1px solid #d7d2c8; border-radius:999px; padding:6px 10px; font-size:11px; color:#68737b; margin-bottom:20px; }
    .login-note { margin-top:18px; padding:12px; background:#faf9f6; border:1px solid #e7e3da; border-radius:8px; font-size:11px; color:#68737b; line-height:1.5; }
    </style>
    <div class="login-card">
      <div class="login-brand">CrimeSphere AI</div>
      <div class="login-sub">Investigation Intelligence &amp; Criminal Network Analysis</div>
      <div class="login-role">Secure Role-Based Access</div>
    </div>
    """, unsafe_allow_html=True)
    with st.form("crimesphere_login", clear_on_submit=False):
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
    if submitted:
        users = load_users()
        record = users.get(username.strip().lower())
        if record and record.get("active", True) and record.get("password_hash") == _password_hash(password):
            role = record.get("role", "Police")
            if role not in ROLE_PAGES:
                st.error("Account has an invalid role. Contact an administrator.")
                return
            clean_username = username.strip().lower()
            st.session_state.authenticated = True
            st.session_state.username = clean_username
            st.session_state.role = role
            st.session_state.category = ROLE_CATEGORY[role]
            st.session_state.page = "Dashboard"
            st.session_state.auth_token = _make_auth_token(clean_username, role, record.get("password_hash", ""))
            # Keep authentication in the same browser tab. This token is only
            # used to restore the Streamlit session after a navigation/reconnect.
            st.query_params["auth"] = st.session_state.auth_token
            st.query_params["page"] = "Dashboard"
            st.rerun()
        else:
            st.error("Invalid username/password or inactive account.")
    st.markdown("""<div class="login-note"><b>Access categories</b><br>Category A: Administrators have full application access.<br>Category B: Police and Investigators have operational investigation access; administration/settings are restricted.</div>""", unsafe_allow_html=True)
    st.caption("For the first local run, demo accounts are created automatically. Change their passwords before deployment.")

# Authenticate before loading the investigation workspace.
# If the browser reconnects after clicking a module, restore the same logged-in
# user from the signed token instead of showing the login page again.
if not st.session_state.get("authenticated", False):
    try:
        _restore_auth_from_token(st.query_params.get("auth"))
    except Exception:
        pass

if not st.session_state.get("authenticated", False):
    render_login()
    st.stop()

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
# CASE / DATA-SOURCE UI ENHANCEMENTS
# ============================================================
st.markdown("""
<style>
.data-source-card {
    min-height: 64px;
    box-sizing: border-box;
    border-radius: 10px;
    padding: 12px 16px;
    margin-bottom: 12px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    border: 1px solid transparent;
    font-size: 15px;
}
.data-source-card span { font-weight: 500; }
.data-source-card small { margin-top: 3px; font-size: 11px; opacity: .78; }
.data-source-ok { background: #dff0df; border-color: #c8e4c8; color: #087f43; }
.data-source-warning { background: #f9dddd; border-color: #e7b8b8; color: #a32232; }
.data-source-empty { background: #f1f1ef; border-color: #dedbd4; color: #777; }
.case-detail-card {
    background: #f8f7f3;
    border: 1px solid #dedbd4;
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 12px;
    min-height: 70px;
}
.case-detail-label { font-size: 11px; color: #727b83; text-transform: uppercase; letter-spacing: .6px; }
.case-detail-value { margin-top: 7px; font-size: 16px; color: #20384c; font-weight: 600; word-break: break-word; }
</style>
""", unsafe_allow_html=True)

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

persons_master = read_csv(FILES["persons_master"])
phones = read_csv(FILES["phones"])
vehicles = read_csv(FILES["vehicles"])
vehicle_events = read_csv(FILES["vehicle_events"])
bank_accounts = read_csv(FILES["bank_accounts"])
devices = read_csv(FILES["devices"])
surveillance = read_csv(FILES["surveillance"])
locations_master = read_csv(FILES["locations_master"])
organizations = read_csv(FILES["organizations"])

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
persons_master = clean_id_columns(persons_master)
phones = clean_id_columns(phones)
vehicles = clean_id_columns(vehicles)
vehicle_events = clean_id_columns(vehicle_events)
bank_accounts = clean_id_columns(bank_accounts)
devices = clean_id_columns(devices)
surveillance = clean_id_columns(surveillance)
locations_master = clean_id_columns(locations_master)
organizations = clean_id_columns(organizations)

# ============================================================
# DERIVED METRICS
# These values are expensive to calculate, so cache them between
# Streamlit reruns (module/sidebar clicks).
@st.cache_data(show_spinner=False)
def build_derived_metrics():
    ids = set()

    if "person_id" in assessment.columns:
        ids.update(assessment["person_id"].dropna().astype(str))
    if "person_id" in persons_master.columns:
        ids.update(persons_master["person_id"].dropna().astype(str))

    for df, cols in [
        (cdr, ["caller_person_id", "receiver_person_id"]),
        (transactions, ["sender_person_id", "receiver_person_id"]),
        (locations, ["person_id"]),
        (case_assoc, ["person_id"]),
        (forensic, ["person_id"]),
        (phones, ["person_id"]),
        (vehicles, ["owner_person_id"]),
        (vehicle_events, ["person_id"]),
        (bank_accounts, ["person_id"]),
        (devices, ["person_id"]),
        (surveillance, ["person_id"]),
    ]:
        for col in cols:
            if col in df.columns:
                ids.update(df[col].dropna().astype(str))

    for node, attrs in G.nodes(data=True):
        node_type = str(attrs.get("type", attrs.get("node_type", attrs.get("entity_type", "")))).lower()
        if node_type in {"person", "criminal"} or str(node).startswith("P"):
            ids.add(str(node))

    persons = sorted(x for x in ids if x and x.lower() != "nan")
    valid = set(persons)
    criminal_pairs = set()

    def add_direct_pairs(df, a_col, b_col):
        if df.empty or a_col not in df.columns or b_col not in df.columns:
            return
        for _, row in df[[a_col, b_col]].dropna().iterrows():
            a, b = str(row[a_col]), str(row[b_col])
            if a != b and a in valid and b in valid:
                criminal_pairs.add(tuple(sorted((a, b))))

    add_direct_pairs(cdr, "caller_person_id", "receiver_person_id")
    add_direct_pairs(transactions, "sender_person_id", "receiver_person_id")

    if {"person_id", "location_id"}.issubset(locations.columns):
        for _, group in locations.groupby("location_id"):
            people = sorted(set(group["person_id"].astype(str)) & valid)
            criminal_pairs.update(combinations(people, 2))

    if {"person_id", "case_id"}.issubset(case_assoc.columns):
        for _, group in case_assoc.groupby("case_id"):
            people = sorted(set(group["person_id"].astype(str)) & valid)
            criminal_pairs.update(combinations(people, 2))

    case_ids = set()
    for df in [cases, case_assoc, forensic]:
        if "case_id" in df.columns:
            case_ids.update(df["case_id"].dropna().astype(str))

    high_relevance = 0
    if not assessment.empty and "person_id" in assessment.columns:
        score_col = next((c for c in ["investigative_score", "score", "overall_score"] if c in assessment.columns), None)
        if score_col:
            high_relevance = int(pd.to_numeric(assessment[score_col], errors="coerce").fillna(0).ge(61).sum())

    return {
        "persons": persons,
        "criminal_relationships": len(criminal_pairs),
        "total_cases": len(case_ids),
        "graph_relationships": int(G.number_of_edges()),
        "total_relationships": int(G.number_of_edges()) + len(criminal_pairs),
        "high_relevance": high_relevance,
        "key_network_nodes": int(G.number_of_nodes()),
    }

_metrics = build_derived_metrics()
persons = _metrics["persons"]
criminal_pairs = set()  # kept for compatibility with existing page code
total_criminals = len(persons)
total_cases = _metrics["total_cases"]
graph_relationships = _metrics["graph_relationships"]
criminal_relationships = _metrics["criminal_relationships"]
total_relationships = _metrics["total_relationships"]
high_relevance = _metrics["high_relevance"]
key_network_nodes = _metrics["key_network_nodes"]

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
    ("SUPPORT", [
        ("🆘", "Help & Support"),
        ("📊", "Reports"),
        ("📥", "Complaint Box"),
        ("⚙", "Settings"),
    ]),
]

allowed_pages = set(ROLE_PAGES.get(st.session_state.get("role", "Police"), ROLE_PAGES["Police"]))
NAV = [
    (section, [(icon, label) for icon, label in items if label in allowed_pages])
    for section, items in NAV
]
NAV = [(section, items) for section, items in NAV if items]
valid_pages = [label for _, items in NAV for _, label in items]

# Navigation is kept in the same Streamlit session.
# The sidebar links use the current tab (target=_self) and only update the
# page query parameter; no new tab/window is opened.  Authentication remains
# in session_state, so module navigation does not show the login screen again.
try:
    requested_page = st.query_params.get("page")
except Exception:
    requested_page = None

if requested_page in valid_pages:
    st.session_state.page = requested_page
elif st.session_state.get("page") not in valid_pages:
    st.session_state.page = "Dashboard"

# Preserve the signed login token on every module link.
auth_token = st.session_state.get("auth_token") or st.query_params.get("auth") or ""

# Visible identity / logout control.
# ============================================================
# TOP-RIGHT CLICKABLE USER PROFILE WITH AVATAR
# ============================================================

current_username = st.session_state.get("username", "User")
current_role = st.session_state.get("role", "Police")
current_role_label = ROLE_LABEL.get(current_role, current_role)

profile_initial = current_username[:1].upper() if current_username else "U"

profile_spacer, profile_col = st.columns([8, 2])

with profile_col:
    with st.popover(
        f"👤  {current_username}",
        use_container_width=True
    ):

        st.markdown(
            f'<div style="display:flex;align-items:center;gap:12px;padding:8px 4px 14px 4px;"><div style="width:48px;height:48px;border-radius:50%;background:#243746;color:white;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:700;">{html.escape(profile_initial)}</div><div><div style="font-size:15px;font-weight:700;color:#243746;">{html.escape(current_username)}</div><div style="font-size:12px;color:#68737b;margin-top:3px;">{html.escape(current_role_label)}</div></div></div>',
            unsafe_allow_html=True
        )

        st.divider()

        st.markdown("**👤 Profile**")
        st.write(f"**Username:** {current_username}")
        st.write(f"**Role:** {current_role_label}")

        st.divider()

        if st.button("🚪 Logout", key="profile_logout", use_container_width=True):
            _logout()

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
        nav_query = f"?page={quote(label)}"
        if auth_token:
            nav_query += f"&auth={quote(auth_token)}"
        sidebar_html += (
            f'<a class="nav-link{active}" '
            f'href="{html.escape(nav_query, quote=True)}" '
            f'target="_self">'
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
# AI / INTELLIGENCE CAPABILITY HELPERS
# ============================================================

def _numeric_series(df, candidates):
    for col in candidates:
        if col in df.columns:
            return pd.to_numeric(df[col], errors="coerce")
    return None


def _date_series(df, candidates):
    for col in candidates:
        if col in df.columns:
            return pd.to_datetime(df[col], errors="coerce")
    return None


def _lat_lon_columns(df):
    lat = next((c for c in ["latitude", "lat", "Latitude", "LAT"] if c in df.columns), None)
    lon = next((c for c in ["longitude", "lon", "lng", "Longitude", "LON"] if c in df.columns), None)
    return lat, lon


def build_multisource_person_profile(person):
    """Unify available CDR, transaction, location, case and forensic records."""
    pid = str(person)
    profile = {
        "person_id": pid,
        "cdr_records": 0,
        "transaction_records": 0,
        "location_records": 0,
        "case_records": 0,
        "forensic_records": 0,
        "network_degree": int(G.degree(pid)) if pid in G else 0,
    }
    if {"caller_person_id", "receiver_person_id"}.issubset(cdr.columns):
        profile["cdr_records"] = int((cdr["caller_person_id"].astype(str).eq(pid) | cdr["receiver_person_id"].astype(str).eq(pid)).sum())
    if {"sender_person_id", "receiver_person_id"}.issubset(transactions.columns):
        profile["transaction_records"] = int((transactions["sender_person_id"].astype(str).eq(pid) | transactions["receiver_person_id"].astype(str).eq(pid)).sum())
    if "person_id" in locations.columns:
        profile["location_records"] = int(locations["person_id"].astype(str).eq(pid).sum())
    if "person_id" in case_assoc.columns:
        profile["case_records"] = int(case_assoc["person_id"].astype(str).eq(pid).sum())
    if "person_id" in forensic.columns:
        profile["forensic_records"] = int(forensic["person_id"].astype(str).eq(pid).sum())
    return profile


def explain_score(person):
    """Produce transparent, deterministic score contributors from available evidence."""
    profile = build_multisource_person_profile(person)
    raw = {
        "CDR connections": min(profile["cdr_records"], 20),
        "Financial connections": min(profile["transaction_records"], 20),
        "Location activity": min(profile["location_records"], 20),
        "Case associations": min(profile["case_records"], 20),
        "Forensic records": min(profile["forensic_records"], 20),
    }
    total = sum(raw.values())
    # If a precomputed assessment exists, preserve it as the displayed score.
    displayed = score_for_person(person)
    return raw, displayed, profile


def render_xai_panel(person):
    contributors, displayed, profile = explain_score(person)
    st.markdown("### Explainable AI — Why This Score?")
    st.caption("The panel exposes the available evidence signals behind the investigation indicator. It is not a guilt or probability determination.")
    cols = st.columns(5)
    for col, (label, value) in zip(cols, contributors.items()):
        col.metric(label, value)
    st.progress(int(max(0, min(100, displayed))), text=f"Investigative Score: {displayed:.1f}/100 · {score_range(displayed)}")
    st.dataframe(pd.DataFrame([profile]), use_container_width=True, hide_index=True)


def _person_display_name(person_id):
    """Return the real person name when persons.csv is available."""
    pid = str(person_id)
    if not persons_master.empty and {"person_id", "name"}.issubset(persons_master.columns):
        row = persons_master[persons_master["person_id"].astype(str).eq(pid)]
        if not row.empty:
            value = str(row.iloc[0]["name"]).strip()
            if value and value.lower() != "nan":
                return value
    return pid


def _entity_label(node_type, node_id, person_id=None):
    """Create the compact label shown below an icon node."""
    nid = str(node_id)
    if node_type == "person":
        return _person_display_name(nid)
    if node_type == "phone":
        if not phones.empty and {"phone_id", "phone_number"}.issubset(phones.columns):
            row = phones[phones["phone_id"].astype(str).eq(nid)]
            if not row.empty:
                return str(row.iloc[0]["phone_number"])
        return nid
    if node_type == "vehicle":
        if not vehicles.empty and {"vehicle_id", "registration_number"}.issubset(vehicles.columns):
            row = vehicles[vehicles["vehicle_id"].astype(str).eq(nid)]
            if not row.empty:
                return str(row.iloc[0]["registration_number"])
        return nid
    if node_type == "bank_account":
        if not bank_accounts.empty and {"account_id", "account_number"}.issubset(bank_accounts.columns):
            row = bank_accounts[bank_accounts["account_id"].astype(str).eq(nid)]
            if not row.empty:
                return str(row.iloc[0]["account_number"])
        return nid
    if node_type == "organization":
        if not organizations.empty and {"organization_id", "name"}.issubset(organizations.columns):
            row = organizations[organizations["organization_id"].astype(str).eq(nid)]
            if not row.empty:
                return str(row.iloc[0]["name"])
        return nid
    if node_type == "location":
        if not locations_master.empty and {"location_id", "location_name"}.issubset(locations_master.columns):
            row = locations_master[locations_master["location_id"].astype(str).eq(nid)]
            if not row.empty:
                return str(row.iloc[0]["location_name"])
        return nid
    if node_type == "case":
        if not cases.empty and "case_id" in cases.columns:
            row = cases[cases["case_id"].astype(str).eq(nid)]
            if not row.empty:
                if "crime_type" in row.columns:
                    return f"{nid} · {row.iloc[0]['crime_type']}"
        return nid
    if node_type == "device":
        if not devices.empty and {"device_id", "device_type"}.issubset(devices.columns):
            row = devices[devices["device_id"].astype(str).eq(nid)]
            if not row.empty:
                return f"{nid} · {row.iloc[0]['device_type']}"
        return nid
    return nid


def _add_node(H, node_id, node_type, label=None):
    H.add_node(str(node_id), node_type=node_type, display_label=label or _entity_label(node_type, node_id))


def build_person_to_person_network(person_a, person_b, max_per_type=8):
    """Build a focused multi-source investigation graph around two selected people.

    This deliberately builds the Network Explorer graph from the project's CSV entity
    tables rather than showing the dense all-person GraphML network. That produces the
    person-to-person investigation format shown in the supplied reference image.
    """
    a, b = str(person_a), str(person_b)
    H = nx.Graph()
    _add_node(H, a, "person", _person_display_name(a))
    _add_node(H, b, "person", _person_display_name(b))

    def add_relation(u, v, relation):
        if u == v:
            return
        H.add_edge(str(u), str(v), relationship=relation)

    # Direct CDR person-to-person evidence.
    if {"caller_person_id", "receiver_person_id"}.issubset(cdr.columns):
        mask = (
            ((cdr["caller_person_id"].astype(str) == a) & (cdr["receiver_person_id"].astype(str) == b))
            | ((cdr["caller_person_id"].astype(str) == b) & (cdr["receiver_person_id"].astype(str) == a))
        )
        if int(mask.sum()) > 0:
            add_relation(a, b, f"CALLS · {int(mask.sum())}")

    # Direct financial person-to-person evidence.
    if {"sender_person_id", "receiver_person_id"}.issubset(transactions.columns):
        mask = (
            ((transactions["sender_person_id"].astype(str) == a) & (transactions["receiver_person_id"].astype(str) == b))
            | ((transactions["sender_person_id"].astype(str) == b) & (transactions["receiver_person_id"].astype(str) == a))
        )
        if int(mask.sum()) > 0:
            if H.has_edge(a, b):
                H[a][b]["relationship"] += f" · FINANCIAL · {int(mask.sum())}"
            else:
                add_relation(a, b, f"FINANCIAL · {int(mask.sum())}")

    people = [a, b]
    for pid in people:
        # Phones
        if {"phone_id", "person_id"}.issubset(phones.columns):
            rows = phones[phones["person_id"].astype(str).eq(pid)].head(max_per_type)
            for _, r in rows.iterrows():
                nid = f"PH:{r['phone_id']}"
                _add_node(H, nid, "phone", str(r.get("phone_number", r["phone_id"])))
                add_relation(pid, nid, "PHONE")

        # Vehicles: owner + event vehicles used by the person.
        vehicle_ids = []
        if {"vehicle_id", "owner_person_id"}.issubset(vehicles.columns):
            vehicle_ids.extend(vehicles.loc[vehicles["owner_person_id"].astype(str).eq(pid), "vehicle_id"].astype(str).tolist())
        if {"vehicle_id", "person_id"}.issubset(vehicle_events.columns):
            vehicle_ids.extend(vehicle_events.loc[vehicle_events["person_id"].astype(str).eq(pid), "vehicle_id"].astype(str).tolist())
        for vid in list(dict.fromkeys(vehicle_ids))[:max_per_type]:
            nid = f"VEH:{vid}"
            _add_node(H, nid, "vehicle", _entity_label("vehicle", vid))
            add_relation(pid, nid, "VEHICLE")

        # Bank accounts
        if {"account_id", "person_id"}.issubset(bank_accounts.columns):
            rows = bank_accounts[bank_accounts["person_id"].astype(str).eq(pid)].head(max_per_type)
            for _, r in rows.iterrows():
                aid = str(r["account_id"])
                nid = f"BA:{aid}"
                _add_node(H, nid, "bank_account", _entity_label("bank_account", aid))
                add_relation(pid, nid, "BANK ACCOUNT")

        # Devices
        if {"device_id", "person_id"}.issubset(devices.columns):
            rows = devices[devices["person_id"].astype(str).eq(pid)].head(max_per_type)
            for _, r in rows.iterrows():
                did = str(r["device_id"])
                nid = f"DEV:{did}"
                _add_node(H, nid, "device", _entity_label("device", did))
                add_relation(pid, nid, "DEVICE")

        # Locations from both location events and surveillance events.
        loc_ids = []
        if {"person_id", "location_id"}.issubset(locations.columns):
            loc_ids.extend(locations.loc[locations["person_id"].astype(str).eq(pid), "location_id"].astype(str).tolist())
        if {"person_id", "location_id"}.issubset(surveillance.columns):
            loc_ids.extend(surveillance.loc[surveillance["person_id"].astype(str).eq(pid), "location_id"].astype(str).tolist())
        for lid in list(dict.fromkeys(loc_ids))[:max_per_type]:
            nid = f"LOC:{lid}"
            _add_node(H, nid, "location", _entity_label("location", lid))
            add_relation(pid, nid, "LOCATION")

        # Cases associated with the person.
        if {"person_id", "case_id"}.issubset(case_assoc.columns):
            rows = case_assoc[case_assoc["person_id"].astype(str).eq(pid)].head(max_per_type)
            for _, r in rows.iterrows():
                cid = str(r["case_id"])
                nid = f"CASE:{cid}"
                _add_node(H, nid, "case", _entity_label("case", cid))
                add_relation(pid, nid, "CASE")

        # Forensic evidence as individual evidence nodes.
        if {"person_id", "report_id"}.issubset(forensic.columns):
            rows = forensic[forensic["person_id"].astype(str).eq(pid)].head(max_per_type)
            for _, r in rows.iterrows():
                eid = str(r["report_id"])
                nid = f"EVD:{eid}"
                _add_node(H, nid, "evidence", eid)
                add_relation(pid, nid, "EVIDENCE")

        # Bring across organization nodes only when the existing GraphML proves a
        # person-to-organization edge. There is no fabricated person-org mapping.
        if pid in G:
            for n in G.neighbors(pid):
                attrs = G.nodes[n]
                raw_type = str(attrs.get("type", attrs.get("node_type", attrs.get("entity_type", "")))).lower()
                if raw_type in {"organization", "org", "company"}:
                    nid = f"ORG:{n}"
                    _add_node(H, nid, "organization", str(attrs.get("name", n)))
                    add_relation(pid, nid, "ORGANIZATION")

    # Explicit common entities make the person-to-person investigation relationship
    # visible even when there is no direct person-person edge.
    for prefix, typ in [("LOC:", "location"), ("CASE:", "case")]:
        shared = [n for n in H.nodes if str(n).startswith(prefix) and H.has_edge(a, n) and H.has_edge(b, n)]
        for n in shared:
            H[a][n]["relationship"] = "COMMON LOCATION" if typ == "location" else "COMMON CASE"
            H[b][n]["relationship"] = H[a][n]["relationship"]

    # Also show direct common vehicles/accounts/devices as shared evidence links.
    for prefix, rel in [("VEH:", "COMMON VEHICLE"), ("BA:", "COMMON BANK ACCOUNT"), ("DEV:", "COMMON DEVICE")]:
        for n in [n for n in H.nodes if str(n).startswith(prefix) and H.has_edge(a, n) and H.has_edge(b, n)]:
            H[a][n]["relationship"] = rel
            H[b][n]["relationship"] = rel

    return H


def render_person_to_person_network(person_a, person_b):
    """Render the Network Explorer graph as browser SVG so Windows emoji render natively."""
    H = build_person_to_person_network(person_a, person_b)
    if H.number_of_nodes() < 2:
        st.info("Not enough entity records are available for the selected people.")
        return

    st.markdown("### Person-to-Person Investigation Network")
    st.caption(
        f"{_person_display_name(person_a)} ↔ {_person_display_name(person_b)} · 2023 – 2026 · Multi-source evidence view"
    )

    ICONS = {
        "person": "👤", "phone": "☎", "vehicle": "🚗",
        "bank_account": "🏦", "organization": "🏢", "location": "📍",
        "case": "📁", "device": "💻", "evidence": "E",
    }
    COLORS = {
        "person": "#2B78B5", "phone": "#4B82C4", "vehicle": "#4E9B51",
        "bank_account": "#D18A2B", "organization": "#8B5FA7", "location": "#C96D43",
        "case": "#B35B7C", "device": "#3E8F8F", "evidence": "#7C6A50",
    }

    people = [str(person_a), str(person_b)]
    entities = [n for n in H.nodes if n not in people]
    entities.sort(key=lambda n: (str(H.nodes[n].get("node_type", "")), str(n)))

    W, HGT = 1120, 690
    positions = {people[0]: (430, 335), people[1]: (650, 335)}
    rings = [[], [], []]
    for i, n in enumerate(entities):
        rings[min(i // 12, 2)].append(n)
    radii = [(260, 185), (370, 260), (450, 315)]
    for ring_idx, nodes in enumerate(rings):
        if not nodes:
            continue
        rx, ry = radii[ring_idx]
        count = len(nodes)
        for j, n in enumerate(nodes):
            angle = (2 * np.pi * j / count) - np.pi / 2 + (0.10 * ring_idx)
            positions[n] = (540 + rx * np.cos(angle), 345 + ry * np.sin(angle))

    def esc(v):
        return html.escape(str(v), quote=True)

    svg = [f"""<div style=\"width:100%;background:#fff;border:1px solid #e2e5e8;border-radius:12px;overflow:hidden;\">
    <svg viewBox=\"0 0 {W} {HGT}\" width=\"100%\" role=\"img\" aria-label=\"Person to person investigation network\" style=\"display:block;background:#fff;font-family:Segoe UI,Arial,sans-serif;\">
      <defs><filter id=\"softShadow\" x=\"-30%\" y=\"-30%\" width=\"160%\" height=\"160%\"><feDropShadow dx=\"0\" dy=\"2\" stdDeviation=\"3\" flood-opacity=\"0.16\"/></filter></defs>
      <text x=\"560\" y=\"34\" text-anchor=\"middle\" font-size=\"23\" font-weight=\"700\" fill=\"#25313A\">Person-to-Person Investigation Network</text>
      <text x=\"560\" y=\"55\" text-anchor=\"middle\" font-size=\"11\" fill=\"#7A858D\">{esc(_person_display_name(person_a))} ↔ {esc(_person_display_name(person_b))} · 2023 – 2026</text>
      <rect x=\"18\" y=\"75\" width=\"1084\" height=\"570\" rx=\"10\" fill=\"#FFFFFF\"/>
    """]

    edge_colors = {
        "PHONE": "#6B8FD3", "VEHICLE": "#6FA56F", "BANK ACCOUNT": "#D5A15A",
        "DEVICE": "#69A6A6", "LOCATION": "#D28A67", "CASE": "#BF7894",
        "EVIDENCE": "#9C8A70", "ORGANIZATION": "#9873AD", "COMMON LOCATION": "#DF6D9C",
        "COMMON CASE": "#C95880", "COMMON VEHICLE": "#55A05A", "COMMON BANK ACCOUNT": "#D18A2B",
        "COMMON DEVICE": "#4B9999",
    }
    for u, v, data in H.edges(data=True):
        if u not in positions or v not in positions:
            continue
        x1, y1 = positions[u]; x2, y2 = positions[v]
        rel = str(data.get("relationship", "RELATED"))
        base = rel.split(" · ")[0]
        if "FINANCIAL" in rel:
            edge_color = "#C98B36"
        elif "CALLS" in rel:
            edge_color = "#5B8FF9"
        else:
            edge_color = edge_colors.get(base, "#A5A9AD")
        direct = set([u, v]) == set(people)
        width = 3 if direct else 1.25
        opacity = 0.75 if direct else 0.42
        svg.append(f'<line x1=\"{x1:.1f}\" y1=\"{y1:.1f}\" x2=\"{x2:.1f}\" y2=\"{y2:.1f}\" stroke=\"{edge_color}\" stroke-width=\"{width}\" opacity=\"{opacity}\"/>')

    if H.has_edge(people[0], people[1]):
        svg.append('<text x=\"540\" y=\"300\" text-anchor=\"middle\" font-size=\"9\" font-weight=\"700\" fill=\"#4C708C\">PERSON ↔ PERSON</text>')

    for node in H.nodes:
        typ = str(H.nodes[node].get("node_type", "evidence"))
        x, y = positions[node]
        central = node in people
        r = 31 if central else 21
        stroke = COLORS.get(typ, "#7C6A50")
        fill = "#EAF3FB" if central else "#FFFFFF"
        icon = ICONS.get(typ, "E")
        label = str(H.nodes[node].get("display_label", node))
        if len(label) > 25:
            label = label[:22] + "…"
        label_y = y + r + 16
        icon_size = 25 if central else 19
        svg.append('<g filter=\"url(#softShadow)\">')
        svg.append(f'<circle cx=\"{x:.1f}\" cy=\"{y:.1f}\" r=\"{r}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"2.4\"/>')
        svg.append(f'<text x=\"{x:.1f}\" y=\"{y + icon_size*0.34:.1f}\" text-anchor=\"middle\" font-size=\"{icon_size}px\" font-weight=\"700\" fill=\"{stroke}\">{esc(icon)}</text>')
        svg.append('</g>')
        svg.append(f'<text x=\"{x:.1f}\" y=\"{label_y:.1f}\" text-anchor=\"middle\" font-size=\"{9.5 if central else 8}px\" font-weight=\"{700 if central else 400}\" fill=\"#343A40\">{esc(label)}</text>')

    lx, ly = 900, 115
    svg.append(f'<text x=\"{lx}\" y=\"{ly}\" font-size=\"12\" font-weight=\"700\" fill=\"#34414A\">Node Legend</text>')
    legend = [("person", "Person"), ("phone", "Phone"), ("vehicle", "Vehicle"), ("bank_account", "Bank Account"), ("organization", "Organization"), ("location", "Location"), ("case", "Case"), ("device", "Device"), ("evidence", "Evidence")]
    for i, (typ, name) in enumerate(legend):
        yy = ly + 25 + i * 29
        svg.append(f'<circle cx=\"{lx+8}\" cy=\"{yy}\" r=\"9\" fill=\"#fff\" stroke=\"{COLORS[typ]}\" stroke-width=\"1.8\"/>')
        svg.append(f'<text x=\"{lx+8}\" y=\"{yy+3.5}\" text-anchor=\"middle\" font-size=\"10\">{esc(ICONS[typ])}</text>')
        svg.append(f'<text x=\"{lx+25}\" y=\"{yy+4}\" font-size=\"9.5\" fill=\"#56616A\">{esc(name)}</text>')

    svg.append(f'<text x=\"560\" y=\"625\" text-anchor=\"middle\" font-size=\"9.5\" fill=\"#7A838A\">Visible nodes: {H.number_of_nodes()}  •  Relationships: {H.number_of_edges()}</text>')
    svg.append('</svg></div>')
    components.html("".join(svg), height=720, scrolling=False)
    return H




# ============================================================
# RESTORED CORE PAGE RENDERERS
# ============================================================

def render_geospatial_intelligence():
    """Render geospatial intelligence by joining location events to the location master.

    The project stores event coordinates indirectly: location_events.csv contains
    location_id, while locations.csv contains latitude/longitude. This function
    resolves that relationship automatically and never requires editing the CSVs.
    """
    st.markdown("### Predictive Analytics & Geospatial Intelligence")
    st.caption("Location activity is mapped from location events joined to the location master dataset.")

    if locations.empty:
        st.info("No location-event data is available for geospatial analysis.")
        return

    # ------------------------------------------------------------
    # 1. Build a geographic event table.
    #    location_events.csv normally has location_id but no coordinates.
    #    locations.csv supplies latitude/longitude for that location_id.
    # ------------------------------------------------------------
    geo = locations.copy()

    # Normalize the join key even if one dataset was loaded with numeric IDs.
    if "location_id" in geo.columns:
        geo["location_id"] = geo["location_id"].astype(str).str.strip()

    master = locations_master.copy() if not locations_master.empty else pd.DataFrame()
    if not master.empty and "location_id" in master.columns:
        master["location_id"] = master["location_id"].astype(str).str.strip()

        # Prefer the authoritative master coordinates whenever the event table
        # doesn't already contain valid coordinates.
        lat_master = next((c for c in ["latitude", "lat", "Latitude", "LATITUDE"] if c in master.columns), None)
        lon_master = next((c for c in ["longitude", "lon", "lng", "Longitude", "LONGITUDE"] if c in master.columns), None)

        if lat_master and lon_master and "location_id" in geo.columns:
            master_geo = master[["location_id", lat_master, lon_master] +
                                [c for c in ["location_name", "city"] if c in master.columns]].copy()
            master_geo = master_geo.drop_duplicates(subset=["location_id"])
            geo = geo.merge(master_geo, on="location_id", how="left", suffixes=("", "_master"))

            # If event data has coordinate columns, use them when valid; otherwise
            # fill them from locations.csv.
            event_lat = next((c for c in ["latitude", "lat", "Latitude", "LATITUDE"] if c in geo.columns), None)
            event_lon = next((c for c in ["longitude", "lon", "lng", "Longitude", "LONGITUDE"] if c in geo.columns), None)

            if event_lat:
                geo["_latitude"] = pd.to_numeric(geo[event_lat], errors="coerce")
            else:
                geo["_latitude"] = np.nan
            if event_lon:
                geo["_longitude"] = pd.to_numeric(geo[event_lon], errors="coerce")
            else:
                geo["_longitude"] = np.nan

            geo["_latitude"] = geo["_latitude"].fillna(pd.to_numeric(geo[lat_master], errors="coerce"))
            geo["_longitude"] = geo["_longitude"].fillna(pd.to_numeric(geo[lon_master], errors="coerce"))

            if "location_name_master" in geo.columns and "location_name" not in geo.columns:
                geo["location_name"] = geo["location_name_master"]
            elif "location_name_master" in geo.columns:
                geo["location_name"] = geo["location_name"].fillna(geo["location_name_master"])

            if "city_master" in geo.columns and "city" not in geo.columns:
                geo["city"] = geo["city_master"]
            elif "city_master" in geo.columns:
                geo["city"] = geo["city"].fillna(geo["city_master"])
        else:
            geo["_latitude"] = np.nan
            geo["_longitude"] = np.nan
    else:
        # Fallback: use coordinates directly from location events if present.
        lat_col, lon_col = _lat_lon_columns(geo)
        geo["_latitude"] = pd.to_numeric(geo[lat_col], errors="coerce") if lat_col else np.nan
        geo["_longitude"] = pd.to_numeric(geo[lon_col], errors="coerce") if lon_col else np.nan

    geo["_latitude"] = pd.to_numeric(geo["_latitude"], errors="coerce")
    geo["_longitude"] = pd.to_numeric(geo["_longitude"], errors="coerce")

    # Remove impossible coordinates and rows without a resolvable location.
    geo = geo[
        geo["_latitude"].between(-90, 90, inclusive="both") &
        geo["_longitude"].between(-180, 180, inclusive="both")
    ].copy()

    if geo.empty:
        st.error(
            "Location events were found, but no valid coordinates could be resolved. "
            "Make sure locations.csv contains location_id, latitude and longitude."
        )
        return

    # ------------------------------------------------------------
    # 2. Summary metrics.
    # ------------------------------------------------------------
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Recorded Events", f"{len(geo):,}")
    c2.metric("Mapped Locations", f"{geo['location_id'].nunique() if 'location_id' in geo.columns else len(geo):,}")
    c3.metric("Persons Observed", f"{geo['person_id'].nunique() if 'person_id' in geo.columns else 0:,}")
    c4.metric("Coordinates Resolved", f"{len(geo):,}")

    # ------------------------------------------------------------
    # 3. Actual activity map.
    # ------------------------------------------------------------
    map_df = geo[["_latitude", "_longitude"]].rename(columns={"_latitude": "lat", "_longitude": "lon"})
    st.markdown("#### Recorded Activity Map")
    st.map(map_df, size=18, zoom=None)

    # ------------------------------------------------------------
    # 4. Activity trend + transparent forecast.
    # ------------------------------------------------------------
    date_col = safe_date_column(
        geo,
        ["event_date", "date", "timestamp", "datetime", "created_at"]
    )

    if date_col:
        parsed_dates = pd.to_datetime(geo[date_col], errors="coerce")
        dated = geo.loc[parsed_dates.notna()].copy()
        dated["_event_datetime"] = parsed_dates.loc[dated.index]

        if not dated.empty:
            dated["period"] = dated["_event_datetime"].dt.to_period("M").astype(str)
            trend = dated.groupby("period").size().reset_index(name="activity")
            trend = trend.sort_values("period")

            st.markdown("#### Hotspot Activity Trend")
            st.line_chart(trend.set_index("period")["activity"], height=280)

            if len(trend) >= 3:
                y = trend["activity"].astype(float).to_numpy()
                x = np.arange(len(y), dtype=float)
                slope, intercept = np.polyfit(x, y, 1)
                forecast = max(0.0, float(slope * len(y) + intercept))
                st.metric("Next-period predicted activity", f"{forecast:.1f}")
                st.caption(
                    "Forecast uses a transparent linear trend over historical location-event counts. "
                    "It is an operational planning indicator, not a certainty about future crime."
                )

            # --------------------------------------------------------
            # 5. Highest-activity locations with names when available.
            # --------------------------------------------------------
            st.markdown("#### Highest-Activity Locations")
            group_cols = ["_latitude", "_longitude"]
            if "location_id" in dated.columns:
                group_cols = ["location_id"] + group_cols

            hotspots = dated.groupby(group_cols).size().reset_index(name="activity")
            hotspots = hotspots.sort_values("activity", ascending=False).head(10)

            if "location_id" in hotspots.columns and not master.empty and "location_id" in master.columns:
                display_cols = [c for c in ["location_id", "location_name", "city", "latitude", "longitude"] if c in master.columns]
                if display_cols:
                    master_display = master[display_cols].drop_duplicates("location_id")
                    hotspots = hotspots.merge(master_display, on="location_id", how="left")

            rename_map = {
                "_latitude": "Latitude",
                "_longitude": "Longitude",
                "activity": "Activity Events",
            }
            hotspots = hotspots.rename(columns=rename_map)
            st.dataframe(hotspots, use_container_width=True, hide_index=True)
        else:
            st.info("No valid event dates are available for the trend and forecast.")
    else:
        st.info("No event-date column was found. The activity map is still available.")


FINGERPRINT_REGISTRY_COLUMNS = [
    "image_id",
    "person_id",
    "case_id",
    "original_filename",
    "stored_filename",
    "stored_path",
    "sha256",
    "uploaded_at",
    "verification_status",
    "notes",
]


def _safe_filename(filename):
    """Return a filesystem-safe filename while preserving the extension."""
    name = Path(str(filename)).name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).stem).strip("._") or "fingerprint"
    suffix = Path(name).suffix.lower()
    if suffix not in {".jpg", ".jpeg"}:
        suffix = ".jpg"
    return f"{stem}{suffix}"


def _load_fingerprint_registry():
    path = FILES["fingerprint_registry"]
    if path.exists():
        try:
            df = pd.read_csv(path, dtype=str).fillna("")
        except Exception:
            df = pd.DataFrame(columns=FINGERPRINT_REGISTRY_COLUMNS)
    else:
        df = pd.DataFrame(columns=FINGERPRINT_REGISTRY_COLUMNS)
    for col in FINGERPRINT_REGISTRY_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    return df[FINGERPRINT_REGISTRY_COLUMNS].copy()


def _save_fingerprint_registry(df):
    path = FILES["fingerprint_registry"]
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def _store_fingerprint_image(uploaded_file, person_id, case_id, notes, verification_status):
    """Persist a JPG/JPEG fingerprint evidence image and its audit metadata."""
    image_bytes = uploaded_file.getvalue()
    digest = hashlib.sha256(image_bytes).hexdigest()
    registry = _load_fingerprint_registry()

    # Avoid storing the same image more than once.
    duplicate = registry[registry["sha256"].astype(str).eq(digest)]
    if not duplicate.empty:
        return duplicate.iloc[0].to_dict(), False

    image_dir = FILES["fingerprint_images_dir"]
    image_dir.mkdir(parents=True, exist_ok=True)

    safe_name = _safe_filename(uploaded_file.name)
    image_id = f"FPIMG-{datetime.now().strftime('%Y%m%d%H%M%S')}-{digest[:10]}"
    stored_filename = f"{image_id}_{safe_name}"
    destination = image_dir / stored_filename
    destination.write_bytes(image_bytes)

    row = {
        "image_id": image_id,
        "person_id": str(person_id),
        "case_id": str(case_id) if case_id else "",
        "original_filename": str(uploaded_file.name),
        "stored_filename": stored_filename,
        "stored_path": str(destination.relative_to(DATA_DIR)),
        "sha256": digest,
        "uploaded_at": datetime.now().isoformat(timespec="seconds"),
        "verification_status": str(verification_status),
        "notes": str(notes or ""),
    }
    registry = pd.concat([registry, pd.DataFrame([row])], ignore_index=True)
    _save_fingerprint_registry(registry)
    return row, True


def _render_fingerprint_upload():
    """JPG/JPEG fingerprint evidence upload and manual review registry."""
    st.markdown("### Upload Fingerprint Evidence")
    st.caption(
        "Upload a fingerprint image in JPG/JPEG format and associate it with an existing person/case. "
        "Images are stored locally under data/raw/fingerprint_images and indexed in a separate registry."
    )

    if not persons:
        st.warning("No person records are available, so a fingerprint image cannot be associated with a person yet.")
        return

    upload_cols = st.columns([1, 1, 1])
    with upload_cols[0]:
        selected_person = st.selectbox(
            "Person",
            persons,
            key="fingerprint_upload_person",
        )
    with upload_cols[1]:
        case_options = [""]
        if not cases.empty and "case_id" in cases.columns:
            case_options += cases["case_id"].dropna().astype(str).unique().tolist()
        selected_case = st.selectbox(
            "Case (optional)",
            case_options,
            key="fingerprint_upload_case",
        )
    with upload_cols[2]:
        verification_status = st.selectbox(
            "Review status",
            ["Pending Review", "Reviewed", "Manual Match", "Manual No Match"],
            key="fingerprint_upload_status",
        )

    uploaded = st.file_uploader(
        "Choose fingerprint JPG/JPEG",
        type=["jpg", "jpeg"],
        accept_multiple_files=True,
        key="fingerprint_jpg_uploader",
        help="Only JPG/JPEG files are accepted by this uploader.",
    )
    notes = st.text_area(
        "Evidence notes (optional)",
        key="fingerprint_upload_notes",
        placeholder="Source item, examiner note, collection context, or other audit information...",
    )

    if uploaded:
        st.markdown("#### Upload preview")
        preview_cols = st.columns(min(3, len(uploaded)))
        for idx, item in enumerate(uploaded):
            with preview_cols[idx % len(preview_cols)]:
                st.image(item, caption=item.name, use_container_width=True)

        if st.button("Save Fingerprint Evidence", type="primary", key="save_fingerprint_evidence"):
            saved = 0
            duplicates = 0
            for item in uploaded:
                try:
                    _, created = _store_fingerprint_image(
                        item,
                        selected_person,
                        selected_case,
                        notes,
                        verification_status,
                    )
                    if created:
                        saved += 1
                    else:
                        duplicates += 1
                except Exception as exc:
                    st.error(f"Could not save {item.name}: {exc}")
            if saved:
                st.success(f"Saved {saved} fingerprint image(s) for {selected_person}.")
            if duplicates:
                st.info(f"Skipped {duplicates} duplicate image(s) based on SHA-256 hash.")
            st.rerun()


def _render_fingerprint_registry():
    registry = _load_fingerprint_registry()
    st.markdown("### Uploaded Fingerprint Evidence")
    if registry.empty:
        st.info("No JPG/JPEG fingerprint images have been uploaded yet.")
        return

    filter_cols = st.columns(3)
    with filter_cols[0]:
        person_filter = st.selectbox(
            "Filter by person",
            ["All"] + sorted(registry["person_id"].astype(str).unique().tolist()),
            key="fingerprint_registry_person",
        )
    with filter_cols[1]:
        status_filter = st.selectbox(
            "Filter by status",
            ["All"] + sorted(registry["verification_status"].astype(str).unique().tolist()),
            key="fingerprint_registry_status",
        )
    with filter_cols[2]:
        case_filter = st.selectbox(
            "Filter by case",
            ["All"] + sorted([x for x in registry["case_id"].astype(str).unique().tolist() if x]),
            key="fingerprint_registry_case",
        )

    filtered = registry.copy()
    if person_filter != "All":
        filtered = filtered[filtered["person_id"].astype(str).eq(person_filter)]
    if status_filter != "All":
        filtered = filtered[filtered["verification_status"].astype(str).eq(status_filter)]
    if case_filter != "All":
        filtered = filtered[filtered["case_id"].astype(str).eq(case_filter)]

    st.dataframe(
        filtered.drop(columns=["sha256", "stored_path"], errors="ignore"),
        use_container_width=True,
        hide_index=True,
    )

    if not filtered.empty:
        selected_image_id = st.selectbox(
            "Preview uploaded fingerprint",
            filtered["image_id"].tolist(),
            key="fingerprint_preview_id",
        )
        row = filtered[filtered["image_id"].eq(selected_image_id)].iloc[0]
        image_path = DATA_DIR / row["stored_path"]
        if image_path.exists():
            st.image(
                str(image_path),
                caption=f"{row['original_filename']} · {row['person_id']} · {row['verification_status']}",
                width=420,
            )
        else:
            st.warning("The registry entry exists, but its image file could not be found on disk.")


def render_biometric_intelligence():
    """Biometric evidence management: forensic records plus JPG/JPEG uploads."""
    st.markdown("### Biometric & Forensic Intelligence")
    st.caption(
        "Fingerprint images can be uploaded and associated with a person or case for forensic evidence management. "
        "This application does not perform automated fingerprint identification or authenticate a person's identity from an uploaded image. "
        "Any match decision must come from a validated forensic process and authorized human review."
    )

    _render_fingerprint_upload()
    _render_fingerprint_registry()

    st.markdown("### Forensic Report Register")
    if forensic.empty:
        st.info("No forensic fingerprint report records are available in the CSV dataset.")
        return

    status_col = next((c for c in ["match_status", "status", "match_result"] if c in forensic.columns), None)
    if status_col:
        status_counts = forensic[status_col].fillna("Unknown").astype(str).value_counts()
        st.bar_chart(status_counts, height=280)
    cols = st.columns(4)
    cols[0].metric("Fingerprint reports", len(forensic))
    cols[1].metric("Unique persons", forensic["person_id"].nunique() if "person_id" in forensic.columns else 0)
    cols[2].metric("Unique cases", forensic["case_id"].nunique() if "case_id" in forensic.columns else 0)
    cols[3].metric("Match statuses", forensic[status_col].nunique() if status_col else 0)
    st.dataframe(forensic, use_container_width=True, hide_index=True)


def _persist_new_case(case_row, association_row):
    """Persist a newly created case and its primary-person association."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    cases_path = FILES["cases"]
    assoc_path = FILES["case_assoc"]

    current_cases = pd.read_csv(cases_path) if cases_path.exists() else pd.DataFrame()
    current_assoc = pd.read_csv(assoc_path) if assoc_path.exists() else pd.DataFrame()

    # Preserve the existing CSV schema and append only known columns.
    case_columns = list(current_cases.columns) if not current_cases.empty else [
        "case_id", "fir_number", "crime_type", "case_date", "location_id"
    ]
    assoc_columns = list(current_assoc.columns) if not current_assoc.empty else [
        "association_id", "case_id", "person_id", "relationship"
    ]

    case_to_append = {col: case_row.get(col, "") for col in case_columns}
    assoc_to_append = {col: association_row.get(col, "") for col in assoc_columns}

    current_cases = pd.concat([current_cases, pd.DataFrame([case_to_append])], ignore_index=True)
    current_assoc = pd.concat([current_assoc, pd.DataFrame([assoc_to_append])], ignore_index=True)

    current_cases.to_csv(cases_path, index=False)
    current_assoc.to_csv(assoc_path, index=False)


def _next_case_id():
    """Generate the next C### case identifier without overwriting an existing case."""
    existing = set(cases.get("case_id", pd.Series(dtype=str)).dropna().astype(str)) if not cases.empty else set()
    numbers = []
    for value in existing:
        m = re.fullmatch(r"C(\d+)", value.strip(), flags=re.I)
        if m:
            numbers.append(int(m.group(1)))
    n = max(numbers, default=0) + 1
    candidate = f"C{n:03d}"
    while candidate in existing:
        n += 1
        candidate = f"C{n:03d}"
    return candidate


def _next_association_id():
    existing = set(case_assoc.get("association_id", pd.Series(dtype=str)).dropna().astype(str)) if not case_assoc.empty else set()
    numbers = []
    for value in existing:
        m = re.fullmatch(r"CA(\d+)", value.strip(), flags=re.I)
        if m:
            numbers.append(int(m.group(1)))
    n = max(numbers, default=0) + 1
    candidate = f"CA{n:03d}"
    while candidate in existing:
        n += 1
        candidate = f"CA{n:03d}"
    return candidate


def _open_case_person(person_id, case_id=None):
    """Open Individual Investigation for the selected case/person."""
    st.session_state.page = "Individual Investigation"
    st.session_state.individual_investigation_select = str(person_id)
    if case_id:
        st.session_state.selected_case_id = str(case_id)
    st.rerun()

def is_admin():
    return st.session_state.get("role") == "Admin"


def is_police():
    return st.session_state.get("role") == "Police"


def is_investigator():
    return st.session_state.get("role") == "Investigator"


def can_manage_cases():
    return is_admin()
def render_new_case_form():
    if not is_admin():
        st.error("Administrator access required.")
        return
    """Interactive new-case form available directly from the Dashboard."""
    st.markdown("### Create New Case")
    st.caption("Add a case to the existing case register and optionally link its primary person. The data is written to data/raw/cases.csv and case_associations.csv.")

    with st.form("new_case_form", clear_on_submit=True):
        c1, c2 = st.columns(2)
        with c1:
            case_id_input = st.text_input("Case ID", value=_next_case_id(), help="Leave the generated ID unless you have a specific case identifier.")
            fir_number = st.text_input("FIR Number", value=f"FIR-{datetime.now().year}-{len(cases)+1:04d}")
            crime_type = st.text_input("Crime Type", value="Investigation")
        with c2:
            case_date = st.date_input("Case Date", value=datetime.now().date())
            location_options = ["— None —"]
            if not locations_master.empty and "location_id" in locations_master.columns:
                location_options += sorted(locations_master["location_id"].dropna().astype(str).unique().tolist())
            location_id = st.selectbox("Location", location_options)
            person_options = ["— None —"] + persons
            primary_person = st.selectbox(
                "Primary Person",
                person_options,
                format_func=lambda p: "— None —" if p == "— None —" else f"{p} — {_person_display_name(p)}",
            )

        relationship = st.selectbox("Primary Person Relationship", ["Suspect", "Person of Interest", "Witness", "Victim", "Other"], index=0)
        submitted = st.form_submit_button("Create Case", type="primary", use_container_width=True)

    if not submitted:
        return

    case_id = str(case_id_input).strip()
    if not case_id:
        st.error("Case ID cannot be empty.")
        return

    existing_ids = set(cases["case_id"].dropna().astype(str)) if "case_id" in cases.columns else set()
    if case_id in existing_ids:
        st.error(f"Case ID {case_id} already exists. Please use a unique ID.")
        return

    case_row = {
        "case_id": case_id,
        "fir_number": fir_number.strip(),
        "crime_type": crime_type.strip() or "Investigation",
        "case_date": str(case_date),
        "location_id": "" if location_id == "— None —" else location_id,
    }

    association_row = {
        "association_id": _next_association_id(),
        "case_id": case_id,
        "person_id": "" if primary_person == "— None —" else primary_person,
        "relationship": relationship,
    }

    try:
        _persist_new_case(case_row, association_row)
        st.success(f"Case {case_id} created successfully.")
        st.rerun()
    except Exception as exc:
        st.error(f"Could not save the case: {exc}")
def render_case_update_request():
    st.markdown("### Request Case Update")
    st.caption("Your request will be sent to an Administrator for review.")

    with st.form("case_update_request_form", clear_on_submit=True):

        request_type = st.selectbox(
            "Request Type",
            [
                "Add New Case",
                "Update Existing Case",
                "Modify Case Information",
                "Upload Evidence/File",
            ],
        )

        case_id = st.text_input(
            "Case ID",
            placeholder="Example: C001"
        )

        reason = st.text_area(
            "Reason for Request",
            placeholder="Explain why this case needs to be added or updated..."
        )

        uploaded_file = st.file_uploader(
            "Supporting File",
            type=["pdf", "png", "jpg", "jpeg", "csv", "xlsx", "docx"],
        )

        submitted = st.form_submit_button(
            "Send Request",
            type="primary",
            use_container_width=True
        )

    if submitted:

        if not reason.strip():
            st.error("Please enter the reason for the request.")
            return

        username = st.session_state.get("username", "Unknown")
        role = st.session_state.get("role", "Unknown")

        request = {
            "request_id": f"REQ-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "requested_by": username,
            "role": role,
            "case_id": case_id.strip(),
            "request_type": request_type,
            "reason": reason.strip(),
            "file_name": uploaded_file.name if uploaded_file else "",
            "status": "PENDING",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        requests_file = PROCESSED_DIR / "case_update_requests.json"

        try:
            if requests_file.exists():
                requests = json.loads(
                    requests_file.read_text(encoding="utf-8")
                )
            else:
                requests = []

            requests.append(request)

            requests_file.parent.mkdir(parents=True, exist_ok=True)

            requests_file.write_text(
                json.dumps(requests, indent=2),
                encoding="utf-8"
            )

            st.success(
                "Request sent successfully. Administrator will review it."
            )

            st.session_state.show_case_update_request = False
            st.rerun()

        except Exception as exc:
            st.error(f"Could not submit request: {exc}")


def render_admin_notifications():
    if not is_admin():
        return

    requests_file = PROCESSED_DIR / "case_update_requests.json"

    if not requests_file.exists():
        return

    try:
        requests = json.loads(
            requests_file.read_text(encoding="utf-8")
        )
    except Exception:
        requests = []

    pending = [
        r for r in requests
        if r.get("status") == "PENDING"
    ]

    if pending:
        st.markdown("### 🔔 Case Update Requests")

        st.warning(
            f"You have {len(pending)} pending case update request(s)."
        )

        for request in pending:

            with st.expander(
                f"🔴 {request.get('request_id')} — "
                f"{request.get('request_type')}"
            ):

                st.write(
                    f"**Requested By:** {request.get('requested_by')}"
                )

                st.write(
                    f"**Role:** {request.get('role')}"
                )

                st.write(
                    f"**Case ID:** {request.get('case_id') or 'New Case'}"
                )

                st.write(
                    f"**Reason:** {request.get('reason')}"
                )

                st.write(
                    f"**Time:** {request.get('created_at')}"
                )

                c1, c2 = st.columns(2)

                with c1:
                    if st.button(
                        "Approve",
                        key=f"approve_{request['request_id']}"
                    ):

                        request["status"] = "APPROVED"
                        request["reviewed_by"] = st.session_state.get(
                            "username",
                            "admin"
                        )
                        request["reviewed_at"] = datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )

                        requests_file.write_text(
                            json.dumps(requests, indent=2),
                            encoding="utf-8"
                        )

                        st.success("Request approved.")
                        st.rerun()

                with c2:
                    if st.button(
                        "Reject",
                        key=f"reject_{request['request_id']}"
                    ):

                        request["status"] = "REJECTED"
                        request["reviewed_by"] = st.session_state.get(
                            "username",
                            "admin"
                        )
                        request["reviewed_at"] = datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )

                        requests_file.write_text(
                            json.dumps(requests, indent=2),
                            encoding="utf-8"
                        )

                        st.warning("Request rejected.")
                        st.rerun()


# ============================================================
# HELP & SUPPORT / COMPLAINT WORKFLOW
# Police and Investigators can raise complaints; Admins review them.
# ============================================================

# Shared complaint database. When this Streamlit app is hosted on one machine/server,
# every laptop connecting to that same app URL reads and writes the same SQLite DB.
COMPLAINTS_DB = PROCESSED_DIR / "support_complaints.db"
COMPLAINTS_FILE = PROCESSED_DIR / "support_complaints.json"  # legacy file, migrated automatically

COMPLAINT_TYPES = [
    "Case / FIR issue",
    "Evidence / Forensic issue",
    "CDR / Communication issue",
    "Transaction / Financial issue",
    "Surveillance issue",
    "Location / Timeline issue",
    "Network / Relationship issue",
    "Data access / Missing records",
    "Technical / System issue",
    "Other",
]

def _init_complaints_db():
    COMPLAINTS_DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(COMPLAINTS_DB, timeout=10) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS complaints (
                complaint_id TEXT PRIMARY KEY,
                submitted_by TEXT NOT NULL,
                role TEXT NOT NULL,
                type TEXT NOT NULL,
                related_case TEXT DEFAULT '',
                priority TEXT NOT NULL,
                complaint TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                created_at TEXT NOT NULL,
                reviewed_by TEXT DEFAULT '',
                reviewed_at TEXT DEFAULT '',
                admin_note TEXT DEFAULT ''
            )
        """)
        # One-time migration from the previous JSON complaint store.
        if COMPLAINTS_FILE.exists():
            try:
                count = conn.execute("SELECT COUNT(*) FROM complaints").fetchone()[0]
                if count == 0:
                    data = json.loads(COMPLAINTS_FILE.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        for item in data:
                            conn.execute(
                                """INSERT OR IGNORE INTO complaints
                                (complaint_id, submitted_by, role, type, related_case, priority, complaint, status, created_at, reviewed_by, reviewed_at, admin_note)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (item.get("complaint_id", ""), item.get("submitted_by", "user"),
                                 item.get("role", "Police"), item.get("type", "Other"),
                                 item.get("related_case", ""), item.get("priority", "Medium"),
                                 item.get("complaint", ""), item.get("status", "PENDING"),
                                 item.get("created_at", ""), item.get("reviewed_by", ""),
                                 item.get("reviewed_at", ""), item.get("admin_note", ""))
                            )
            except Exception:
                pass


def _load_complaints():
    try:
        _init_complaints_db()
        with sqlite3.connect(COMPLAINTS_DB, timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM complaints ORDER BY created_at DESC").fetchall()
            return [dict(row) for row in rows]
    except Exception:
        return []

def _save_complaints(items):
    _init_complaints_db()
    with sqlite3.connect(COMPLAINTS_DB, timeout=10) as conn:
        conn.execute("DELETE FROM complaints")
        for item in items:
            conn.execute(
                """INSERT INTO complaints
                (complaint_id, submitted_by, role, type, related_case, priority, complaint, status, created_at, reviewed_by, reviewed_at, admin_note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (item.get("complaint_id", ""), item.get("submitted_by", "user"),
                 item.get("role", "Police"), item.get("type", "Other"),
                 item.get("related_case", ""), item.get("priority", "Medium"),
                 item.get("complaint", ""), item.get("status", "PENDING"),
                 item.get("created_at", ""), item.get("reviewed_by", ""),
                 item.get("reviewed_at", ""), item.get("admin_note", ""))
            )

def render_help_support():
    st.markdown(
        '<div class="page-title-row"><div><div class="page-title">Help &amp; Support</div>'
        '<div class="platform-label">Raise an operational complaint or report an issue to the administrator</div></div>'
        '<div class="case-badge">SUPPORT</div></div>', unsafe_allow_html=True)

    st.info("Use this section for case, evidence, intelligence-data, access, or technical issues. The administrator will review your complaint.")
    complaints = _load_complaints()
    username = st.session_state.get("username", "user")
    role = st.session_state.get("role", "Police")

    with st.form("raise_complaint_form", clear_on_submit=True):
        complaint_type = st.selectbox("Complaint type", COMPLAINT_TYPES)
        related_case = st.text_input("Related Case ID (optional)", placeholder="Example: C004")
        priority = st.selectbox("Priority", ["Low", "Medium", "High", "Critical"], index=1)
        complaint = st.text_area("Describe your complaint", placeholder="Type your complaint here...", height=150)
        submitted = st.form_submit_button("Submit Complaint", type="primary", use_container_width=True)

    if submitted:
        if not complaint.strip():
            st.error("Please enter your complaint before submitting.")
        else:
            complaint_id = f"CMP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"
            complaints.append({
                "complaint_id": complaint_id,
                "submitted_by": username,
                "role": role,
                "type": complaint_type,
                "related_case": related_case.strip(),
                "priority": priority,
                "complaint": complaint.strip(),
                "status": "PENDING",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "reviewed_by": "",
                "reviewed_at": "",
                "admin_note": "",
            })
            _save_complaints(complaints)
            st.success(f"Complaint submitted successfully. Reference: {complaint_id}")
            st.rerun()

    mine = [c for c in complaints if c.get("submitted_by") == username]
    if mine:
        st.markdown("### My Complaints")
        for c in reversed(mine):
            status = c.get("status", "PENDING")
            icon = "🟢" if status == "APPROVED" else "🔴" if status == "REJECTED" else "🟡"
            with st.expander(f"{icon} {c.get('complaint_id')} — {c.get('type')} — {status}"):
                st.write(f"**Priority:** {c.get('priority', 'Medium')}")
                st.write(f"**Case:** {c.get('related_case') or 'Not specified'}")
                st.write(f"**Submitted:** {c.get('created_at')}")
                st.write(f"**Complaint:** {c.get('complaint')}")
                if c.get("reviewed_by"):
                    st.write(f"**Reviewed by:** {c.get('reviewed_by')}")
                    st.write(f"**Admin response:** {c.get('admin_note') or 'No additional note.'}")

def render_complaint_box():
    if not is_admin():
        st.error("Complaint Box is available only to administrators.")
        return
    st.markdown(
        '<div class="page-title-row"><div><div class="page-title">Complaint Box</div>'
        '<div class="platform-label">Review complaints raised by Police and Investigators</div></div>'
        '<div class="case-badge">ADMIN REVIEW</div></div>', unsafe_allow_html=True)

    complaints = _load_complaints()
    refresh_col, _ = st.columns([1, 5])
    with refresh_col:
        if st.button("🔄 Refresh", key="refresh_complaints"):
            st.rerun()
    pending = [c for c in complaints if c.get("status") == "PENDING"]
    st.metric("Pending Complaints", len(pending))

    if not complaints:
        st.success("No complaints have been submitted yet.")
        return

    for c in reversed(complaints):
        status = c.get("status", "PENDING")
        icon = "🟡" if status == "PENDING" else "🟢" if status == "APPROVED" else "🔴"
        with st.expander(f"{icon} {c.get('complaint_id')} — {c.get('type')} — {status}"):
            st.write(f"**Raised by:** {c.get('submitted_by')} ({c.get('role')})")
            st.write(f"**Priority:** {c.get('priority', 'Medium')}")
            st.write(f"**Related Case:** {c.get('related_case') or 'Not specified'}")
            st.write(f"**Submitted:** {c.get('created_at')}")
            st.write(f"**Complaint:** {c.get('complaint')}")

            if status == "PENDING":
                admin_note = st.text_area("Admin response / note (optional)", key=f"admin_note_{c['complaint_id']}", height=90)
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Approve", key=f"approve_complaint_{c['complaint_id']}", type="primary", use_container_width=True):
                        c["status"] = "APPROVED"
                        c["reviewed_by"] = st.session_state.get("username", "admin")
                        c["reviewed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        c["admin_note"] = admin_note.strip()
                        _save_complaints(complaints)
                        st.success("Complaint approved.")
                        st.rerun()
                with col2:
                    if st.button("Reject", key=f"reject_complaint_{c['complaint_id']}", use_container_width=True):
                        c["status"] = "REJECTED"
                        c["reviewed_by"] = st.session_state.get("username", "admin")
                        c["reviewed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        c["admin_note"] = admin_note.strip()
                        _save_complaints(complaints)
                        st.warning("Complaint rejected.")
                        st.rerun()
            else:
                st.write(f"**Reviewed by:** {c.get('reviewed_by')}")
                st.write(f"**Reviewed at:** {c.get('reviewed_at')}")
                st.write(f"**Admin response:** {c.get('admin_note') or 'No additional note.'}")

def render_dashboard():
    if is_admin():
        render_admin_notifications()
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

    # Real interactive New Case control.
    # ============================================================
# ROLE-BASED CASE ACTION
# ============================================================

top_left, top_right = st.columns([1, 5])

with top_left:

    if is_admin():

        if st.button(
            "+ New Case",
            type="primary",
            use_container_width=True,
            key="dashboard_new_case"
        ):
            st.session_state.show_new_case_form = not st.session_state.get(
                "show_new_case_form", False
            )

    elif is_police() or is_investigator():

        if st.button(
            "📝 Request Case Update",
            type="primary",
            use_container_width=True,
            key="dashboard_request_case_update"
        ):
            st.session_state.show_case_update_request = not st.session_state.get(
                "show_case_update_request", False
            )

# Admin sees the actual case creation form
if is_admin() and st.session_state.get("show_new_case_form", False):
    render_new_case_form()

# Police / Investigator see request form
if (is_police() or is_investigator()) and st.session_state.get(
    "show_case_update_request", False
):
    render_case_update_request()

    st.markdown(
        """
        <div class="section-card">
            <div class="section-header">
                <div class="section-title">Recent Cases</div>
                <div class="platform-label">Open a case to investigate its primary person</div>
            </div>
        """,
        unsafe_allow_html=True,
    )

    headers = ["Case ID", "Title", "Status", "Primary Person", "Score", "Actions"]
    st.markdown(
        '<div class="case-head">' + "".join(f"<div>{h}</div>" for h in headers) + "</div>",
        unsafe_allow_html=True,
    )

    if cases.empty:
        st.markdown('<div class="empty-row">No cases found. Use + New Case to create one.</div>', unsafe_allow_html=True)
    else:
        recent = cases.copy().head(12)

        primary = {}
        if {"case_id", "person_id"}.issubset(case_assoc.columns):
            for case_id, grp in case_assoc.groupby("case_id"):
                valid = grp[grp["person_id"].notna() & grp["person_id"].astype(str).ne("")]
                if not valid.empty:
                    primary[str(case_id)] = str(valid.iloc[0]["person_id"])

        # Render each row with a real Streamlit View button.
        for idx, (_, row) in enumerate(recent.iterrows()):
            case_id = str(row.get("case_id", "N/A"))
            title = str(row.get("crime_type", row.get("title", "Investigation")))
            person = primary.get(case_id, "—")
            score = score_for_person(person) if person != "—" else 0
            status = score_range(score) if person != "—" else "OPEN"

            row_cols = st.columns([1.0, 1.8, 1.0, 1.4, 0.8, 0.8])
            row_cols[0].write(case_id)
            row_cols[1].write(title)
            row_cols[2].markdown(f"`{status}`")
            row_cols[3].write(person if person != "—" else "Not linked")
            row_cols[4].write(f"{score:.1f}")
            with row_cols[5]:
                if st.button("View", key=f"dashboard_view_case_{case_id}_{idx}", use_container_width=True):
                    if person != "—" and person in persons:
                        _open_case_person(person, case_id)
                    else:
                        st.session_state.page = "Cases"
                        st.session_state.selected_case_id = case_id
                        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        """
        <div class="disclaimer">
            Scores = Investigative Relevance. NOT probability of guilt. Analytical associations are investigative aids and are not legal determinations.
        </div>
        """,
        unsafe_allow_html=True,
    )


def _case_row(case_id):
    """Return a copy of one case row by case_id."""
    if cases.empty or "case_id" not in cases.columns:
        return None
    matches = cases[cases["case_id"].astype(str).eq(str(case_id))]
    if matches.empty:
        return None
    return matches.iloc[0].copy()


def _case_primary_info(case_id):
    """Return the first linked person and relationship for a case."""
    if case_assoc.empty or not {"case_id", "person_id"}.issubset(case_assoc.columns):
        return "—", "—"
    rows = case_assoc[case_assoc["case_id"].astype(str).eq(str(case_id))]
    rows = rows[rows["person_id"].notna() & rows["person_id"].astype(str).ne("")]
    if rows.empty:
        return "—", "—"
    row = rows.iloc[0]
    return str(row.get("person_id", "—")), str(row.get("relationship", "Associated"))


def _save_case_changes(case_id, values):
    """Update the selected case in the source CSV and refresh cached data."""
    path = FILES["cases"]
    current = pd.read_csv(path) if path.exists() else pd.DataFrame()
    if current.empty or "case_id" not in current.columns:
        raise ValueError("Case register is empty or missing the case_id column.")

    mask = current["case_id"].astype(str).eq(str(case_id))
    if not mask.any():
        raise ValueError(f"Case {case_id} was not found.")

    for col in current.columns:
        if col in values:
            current.loc[mask, col] = values[col]
    current.to_csv(path, index=False)
    read_csv.clear()


def _delete_case(case_id):
    """Delete a case and all of its case-association rows."""
    cases_path = FILES["cases"]
    assoc_path = FILES["case_assoc"]

    current_cases = pd.read_csv(cases_path) if cases_path.exists() else pd.DataFrame()
    if current_cases.empty or "case_id" not in current_cases.columns:
        raise ValueError("Case register is empty or missing the case_id column.")

    case_mask = current_cases["case_id"].astype(str).eq(str(case_id))
    if not case_mask.any():
        raise ValueError(f"Case {case_id} was not found.")
    current_cases = current_cases.loc[~case_mask].copy()
    current_cases.to_csv(cases_path, index=False)

    if assoc_path.exists():
        current_assoc = pd.read_csv(assoc_path)
        if "case_id" in current_assoc.columns:
            current_assoc = current_assoc.loc[
                ~current_assoc["case_id"].astype(str).eq(str(case_id))
            ].copy()
            current_assoc.to_csv(assoc_path, index=False)

    read_csv.clear()


def render_case_details(case_id):
    """Display a full case detail view with Admin edit/delete controls."""
    row = _case_row(case_id)
    if row is None:
        st.error(f"Case {case_id} was not found.")
        st.session_state.pop("selected_case_id", None)
        return

    case_id = str(case_id)
    person_id, relationship = _case_primary_info(case_id)
    score = score_for_person(person_id) if person_id != "—" else 0
    status = score_range(score) if person_id != "—" else "OPEN"

    st.markdown(
        f'<div class="page-title-row"><div class="page-title">Case Details — {html.escape(case_id)}</div></div>',
        unsafe_allow_html=True,
    )
    st.caption("Detailed information for the selected investigation case.")

    details = [
        ("Case ID", row.get("case_id", "—")),
        ("FIR Number", row.get("fir_number", "—")),
        ("Crime Type", row.get("crime_type", row.get("title", "—"))),
        ("Case Date", row.get("case_date", "—")),
        ("Location ID", row.get("location_id", "—")),
        ("Primary Person", person_id),
        ("Relationship", relationship),
        ("Investigation Score", f"{score:.1f}"),
        ("Status", status),
    ]

    detail_cols = st.columns(3)
    for i, (label, value) in enumerate(details):
        with detail_cols[i % 3]:
            st.markdown(
                f'<div class="case-detail-card"><div class="case-detail-label">{html.escape(str(label))}</div><div class="case-detail-value">{html.escape(str(value))}</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown("### Case Actions")
    action_cols = st.columns([1, 1, 4])
    with action_cols[0]:
        edit_clicked = st.button(
            "✏️ Edit",
            type="primary",
            use_container_width=True,
            disabled=not is_admin(),
            key=f"case_edit_{case_id}",
        )
    with action_cols[1]:
        delete_clicked = st.button(
            "🗑️ Delete",
            type="secondary",
            use_container_width=True,
            disabled=not is_admin(),
            key=f"case_delete_{case_id}",
        )
    if not is_admin():
        st.caption("Edit and Delete are available to Administrator accounts only.")

    if edit_clicked:
        st.session_state[f"editing_case_{case_id}"] = True
    if delete_clicked:
        st.session_state[f"confirm_delete_case_{case_id}"] = True

    if st.session_state.get(f"confirm_delete_case_{case_id}", False):
        st.warning(f"Are you sure you want to permanently delete case {case_id}? Its case-association records will also be removed.")
        confirm_cols = st.columns([1, 1, 4])
        with confirm_cols[0]:
            if st.button("Yes, Delete", type="primary", key=f"confirm_yes_{case_id}", use_container_width=True):
                try:
                    _delete_case(case_id)
                    st.session_state.pop(f"confirm_delete_case_{case_id}", None)
                    st.session_state.pop(f"editing_case_{case_id}", None)
                    st.session_state.pop("selected_case_id", None)
                    st.success(f"Case {case_id} deleted successfully.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Could not delete case: {exc}")
        with confirm_cols[1]:
            if st.button("Cancel", key=f"confirm_cancel_{case_id}", use_container_width=True):
                st.session_state.pop(f"confirm_delete_case_{case_id}", None)
                st.rerun()

    if st.session_state.get(f"editing_case_{case_id}", False):
        st.markdown("### Edit Case")
        with st.form(f"edit_case_form_{case_id}"):
            c1, c2 = st.columns(2)
            with c1:
                edit_fir = st.text_input("FIR Number", value=str(row.get("fir_number", "")))
                edit_crime = st.text_input("Crime Type", value=str(row.get("crime_type", row.get("title", ""))))
            with c2:
                edit_date = st.text_input("Case Date", value=str(row.get("case_date", "")))
                edit_location = st.text_input("Location ID", value=str(row.get("location_id", "")))
            save_clicked = st.form_submit_button("Save Changes", type="primary", use_container_width=True)

        if save_clicked:
            try:
                _save_case_changes(
                    case_id,
                    {
                        "fir_number": edit_fir.strip(),
                        "crime_type": edit_crime.strip() or "Investigation",
                        "case_date": edit_date.strip(),
                        "location_id": edit_location.strip(),
                    },
                )
                st.session_state.pop(f"editing_case_{case_id}", None)
                st.success(f"Case {case_id} updated successfully.")
                st.rerun()
            except Exception as exc:
                st.error(f"Could not update the case: {exc}")

    if st.button("← Back to Cases", key=f"back_cases_{case_id}"):
        st.session_state.pop("selected_case_id", None)
        st.rerun()


def render_cases():
    st.markdown(
        '<div class="page-title-row"><div class="page-title">Cases</div></div>',
        unsafe_allow_html=True,
    )
    if is_admin():
        st.success("Administrator Mode — You have full case management access.")
    else:
        st.info("Read-only investigation view. Use 'Request Case Update' to request changes.")

    if "selected_case_id" in st.session_state:
        selected_case_id = str(st.session_state.selected_case_id)
    else:
        selected_case_id = ""

    if selected_case_id:
        render_case_details(selected_case_id)
        return

    if cases.empty:
        st.info("No case dataset was found. Use the Dashboard → + New Case button to create a case.")
        if st.button("Go to Dashboard", key="cases_go_dashboard"):
            st.session_state.page = "Dashboard"
            st.rerun()
        return

    st.caption("Select a case below and open its linked primary person for Individual Investigation.")

    primary = {}
    relationship_map = {}
    if {"case_id", "person_id"}.issubset(case_assoc.columns):
        for case_id, grp in case_assoc.groupby("case_id"):
            valid = grp[grp["person_id"].notna() & grp["person_id"].astype(str).ne("")]
            if not valid.empty:
                primary[str(case_id)] = str(valid.iloc[0]["person_id"])
                relationship_map[str(case_id)] = str(valid.iloc[0].get("relationship", "Associated"))

    for idx, (_, row) in enumerate(cases.iterrows()):
        case_id = str(row.get("case_id", "N/A"))
        title = str(row.get("crime_type", row.get("title", "Investigation")))
        person = primary.get(case_id, "—")
        score = score_for_person(person) if person != "—" else 0
        status = score_range(score) if person != "—" else "OPEN"

        cols = st.columns([1.0, 1.6, 1.0, 1.4, 0.9, 1.0])
        cols[0].write(case_id)
        cols[1].write(title)
        cols[2].markdown(f"`{status}`")
        cols[3].write(person if person != "—" else "Not linked")
        cols[4].write(f"{score:.1f}")
        with cols[5]:
            if st.button("View", key=f"cases_view_{case_id}_{idx}", use_container_width=True):
                st.session_state.selected_case_id = case_id
                st.rerun()

    st.markdown("### Case Register")
    st.dataframe(cases, use_container_width=True, hide_index=True)

def render_table_page(title, df):
    st.markdown(
        f'<div class="page-title-row"><div class="page-title">{html.escape(title)}</div></div>',
        unsafe_allow_html=True,
    )
    if df.empty:
        st.info(f"No data available for {title}.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

def render_network_graph_visual(selected=None):
    # Kept as a compatibility wrapper for existing calls.
    if len(persons) < 2:
        st.info("At least two person IDs are required for the investigation network.")
        return
    a = selected if selected in persons else persons[0]
    b = next((p for p in persons if p != a), persons[1])
    return render_person_to_person_network(a, b)


def render_network():
    """Network Explorer: focused person-to-person investigation network."""
    st.markdown(
        '<div class="page-title-row"><div class="page-title">Network Explorer</div></div>',
        unsafe_allow_html=True,
    )

    if len(persons) < 2:
        st.info("At least two person records are required for Network Explorer.")
        return

    # The graph is deliberately controlled by two people, matching the supplied
    # reference instead of rendering the dense all-person GraphML view.
    c1, c2 = st.columns(2)
    with c1:
        a = st.selectbox(
            "Person A",
            persons,
            format_func=lambda p: f"{p} — {_person_display_name(p)}",
            key="network_person_a",
        )
    with c2:
        b_options = [p for p in persons if p != a] or persons
        default_b = st.session_state.get("network_person_b")
        if default_b not in b_options:
            default_b = b_options[0]
        b = st.selectbox(
            "Person B",
            b_options,
            index=b_options.index(default_b),
            format_func=lambda p: f"{p} — {_person_display_name(p)}",
            key="network_person_b",
        )

    H = render_person_to_person_network(a, b)

    st.markdown("### Network Summary")
    summary_cols = st.columns(4)
    summary_cols[0].metric("Selected Persons", 2)
    summary_cols[1].metric("Visible Nodes", H.number_of_nodes())
    summary_cols[2].metric("Relationships", H.number_of_edges())
    summary_cols[3].metric("Network Degree", f"{H.degree(a) + H.degree(b)}")

    st.markdown("### Network Centrality Indicators")
    centrality = nx.degree_centrality(G) if G.number_of_nodes() else {}
    top = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:15]
    if top:
        st.bar_chart(pd.DataFrame(top, columns=["Person", "Centrality"]).set_index("Person"), height=300)
    else:
        st.info("No GraphML centrality data is available.")


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

    render_biometric_intelligence()


# ============================================================
# REPORT CONTEXT / INTELLIGENCE REPORT HELPERS
# ============================================================

def _safe_int(value):
    try:
        return int(value)
    except Exception:
        return 0

def _report_dataset_summary(df):
    """Return a JSON-safe summary for the report workspace."""
    if df is None or getattr(df, "empty", True):
        return {"records": 0, "columns": [], "sample": []}
    sample = []
    try:
        sample = df.head(5).replace({np.nan: None}).to_dict(orient="records")
    except Exception:
        sample = []
    # Convert numpy/pandas scalar values to native Python values.
    def native(v):
        if isinstance(v, dict):
            return {str(k): native(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [native(x) for x in v]
        if hasattr(v, "item"):
            try:
                return v.item()
            except Exception:
                pass
        return v
    return {
        "records": int(len(df)),
        "columns": [str(c) for c in df.columns.tolist()],
        "sample": native(sample),
    }

def build_llm_report_context():
    """
    Build a compact, JSON-safe analytical context from CrimeSphere datasets.
    This function is intentionally local and deterministic so Reports works
    even when no external LLM/API is configured.
    """
    datasets = {
        "cases": cases,
        "cdr_records": cdr,
        "transactions": transactions,
        "locations": locations,
        "case_associations": case_assoc,
        "forensic": forensic,
        "investigative_assessment": assessment,
        "persons": persons_master,
        "phones": phones,
        "vehicles": vehicles,
        "vehicle_events": vehicle_events,
        "bank_accounts": bank_accounts,
        "devices": devices,
        "surveillance": surveillance,
        "organizations": organizations,
    }

    context = {
        "project": "CrimeSphere AI",
        "purpose": "Investigation intelligence and criminal network analysis",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "network": {
            "nodes": int(G.number_of_nodes()) if G is not None else 0,
            "relationships": int(G.number_of_edges()) if G is not None else 0,
        },
        "datasets": {name: _report_dataset_summary(df) for name, df in datasets.items()},
    }

    # Add the most useful high-level assessment information when available.
    if assessment is not None and not assessment.empty:
        context["assessment"] = _report_dataset_summary(assessment)

    return context

def generate_intelligence_report(focus="overall criminal network and cross-source evidence"):
    """
    Generate a deterministic investigation report from the local datasets.
    Returns (report_text, source_label), matching render_reports_ai().
    """
    context = build_llm_report_context()
    ds = context["datasets"]
    network = context["network"]

    def count(name):
        return ds.get(name, {}).get("records", 0)

    lines = [
        "CRIMESPHERE AI — INVESTIGATION INTELLIGENCE REPORT",
        "=" * 56,
        f"Report focus: {focus.strip() or 'overall criminal network and cross-source evidence'}",
        f"Generated: {context['generated_at']}",
        "",
        "1. EXECUTIVE OVERVIEW",
        f"CrimeSphere AI currently contains {count('cases')} case records and "
        f"{count('persons')} person records, with {network['nodes']} network nodes "
        f"and {network['relationships']} relationships available for analysis.",
        "",
        "2. CROSS-SOURCE COVERAGE",
        f"- CDR records: {count('cdr_records')}",
        f"- Financial transactions: {count('transactions')}",
        f"- Location events: {count('locations')}",
        f"- Case associations: {count('case_associations')}",
        f"- Forensic records: {count('forensic')}",
        f"- Surveillance events: {count('surveillance')}",
        f"- Vehicle events: {count('vehicle_events')}",
        "",
        "3. NETWORK ANALYSIS",
        "The network represents relationships between entities derived from the "
        "available investigation datasets. Network connections should be used to "
        "identify relationships and prioritize investigative review, not as a "
        "standalone determination of guilt.",
        "",
        "4. INVESTIGATIVE USE",
        "Investigators can correlate case, communication, financial, location, "
        "vehicle, surveillance and forensic information to identify patterns and "
        "connections that may require further examination.",
        "",
        "5. CAUTION",
        "This report summarizes available data and analytical indicators. It is "
        "not a legal conclusion, proof of guilt, or a substitute for investigator "
        "judgment and verification of source evidence.",
    ]
    return "\n".join(lines), "Local CrimeSphere analytical report"

# ============================================================
# AI INTELLIGENCE REPORTS
# ============================================================

def render_reports_ai():
    st.markdown('<div class="page-title-row"><div class="page-title">Reports</div></div>', unsafe_allow_html=True)
    st.markdown("### AI Intelligence Report Generator")
    focus = st.text_input("Report focus", value="overall criminal network and cross-source evidence")
    if st.button("Generate Intelligence Report", type="primary"):
        with st.spinner("Generating intelligence report..."):
            report, source = generate_intelligence_report(focus)
        st.success(source)
        st.text_area("Generated report", report, height=420)
        st.download_button("Download report", report, file_name="crimesphere_intelligence_report.txt", mime="text/plain")
    st.markdown("### Current Analytical Coverage")
    coverage = build_llm_report_context()
    network = coverage.get("network", {})
    datasets = coverage.get("datasets", {})

    # Investigator-friendly coverage summary — technical JSON is kept hidden below.
    metric_items = [
        ("Cases", datasets.get("cases", {}).get("records", 0)),
        ("Persons", datasets.get("persons", {}).get("records", 0)),
        ("Network Nodes", network.get("nodes", 0)),
        ("Relationships", network.get("relationships", 0)),
        ("CDR Records", datasets.get("cdr_records", {}).get("records", 0)),
        ("Transactions", datasets.get("transactions", {}).get("records", 0)),
    ]
    cols = st.columns(3)
    for i, (label, value) in enumerate(metric_items):
        with cols[i % 3]:
            st.metric(label, f"{int(value):,}")

    st.markdown("#### Data Sources")
    source_items = [
        ("Cases", "cases"),
        ("Communication / CDR", "cdr_records"),
        ("Financial Transactions", "transactions"),
        ("Location Events", "locations"),
        ("Case Associations", "case_associations"),
        ("Forensic Evidence", "forensic"),
        ("Surveillance", "surveillance"),
        ("Vehicle Events", "vehicle_events"),
    ]
    source_cols = st.columns(2)
    # Two intentionally highlighted sources demonstrate that the dashboard
    # can surface data-quality/availability attention items.
    attention_sources = {"Forensic Evidence", "Surveillance"}
    for i, (label, key) in enumerate(source_items):
        records = datasets.get(key, {}).get("records", 0)
        with source_cols[i % 2]:
            if records:
                if label in attention_sources:
                    st.markdown(
                        f'<div class="data-source-card data-source-warning"><span>⚠ {html.escape(label)} — {int(records):,} records</span><small>Attention required</small></div>',
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f'<div class="data-source-card data-source-ok"><span>✓ {html.escape(label)} — {int(records):,} records</span><small>Available</small></div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    f'<div class="data-source-card data-source-empty"><span>○ {html.escape(label)} — No records available</span><small>Unavailable</small></div>',
                    unsafe_allow_html=True,
                )

    st.caption(
        "Coverage reflects the records currently loaded into CrimeSphere AI. "
        "These figures describe available analytical data and do not indicate guilt."
    )

    with st.expander("Technical Details", expanded=False):
        st.json(coverage)

# ============================================================
# ADMIN — USER MANAGEMENT
# ============================================================

def render_admin_user_management():
    if st.session_state.get("role") != "Admin":
        st.error("Administrator access required.")
        return
    st.markdown("### User & Access Management")
    st.caption("Category A administrators can create and deactivate Category B accounts and change account roles.")
    users = load_users()
    rows = []
    for uname, rec in users.items():
        rows.append({"Username": uname, "Category": ROLE_CATEGORY.get(rec.get("role"), ""), "Role": rec.get("role", ""), "Active": bool(rec.get("active", True))})
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with st.expander("Create / update user", expanded=False):
        with st.form("admin_user_form"):
            uname = st.text_input("Username").strip().lower()
            new_password = st.text_input("Password", type="password")
            role = st.selectbox("Role", ["Admin", "Police", "Investigator"])
            active = st.checkbox("Account active", value=True)
            save = st.form_submit_button("Save user", type="primary")
        if save:
            if not re.fullmatch(r"[a-zA-Z0-9._-]{3,40}", uname):
                st.error("Username must be 3–40 characters and use only letters, numbers, dot, underscore or hyphen.")
            elif len(new_password) < 8:
                st.error("Password must contain at least 8 characters.")
            else:
                users[uname] = {"password_hash": _password_hash(new_password), "role": role, "active": active}
                save_users(users)
                st.success(f"User '{uname}' saved as {ROLE_LABEL[role]}.")
                st.rerun()

    with st.expander("Deactivate / reactivate account", expanded=False):
        candidates = [u for u in users if u != st.session_state.get("username")]
        if candidates:
            target = st.selectbox("Account", candidates, key="admin_target_user")
            current = users[target]
            if st.button("Toggle active status", key="admin_toggle_user"):
                current["active"] = not bool(current.get("active", True))
                save_users(users)
                st.success(f"{target} is now {'active' if current['active'] else 'inactive'}.")
                st.rerun()
        else:
            st.info("No other accounts are available to manage.")


# ============================================================
# SETTINGS
# ============================================================

def render_settings():
    st.markdown(
        '<div class="page-title-row"><div class="page-title">Settings</div></div>',
        unsafe_allow_html=True,
    )

    if st.session_state.get("role") == "Admin":
        render_admin_user_management()
        st.divider()

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
        "SYSTEM": ["Reports", "Complaint Box", "Settings"],
        "SUPPORT": ["Help & Support"],
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


def build_individual_investigation_network(person_id, max_per_type=10, max_connected_people=10):
    """Build a focused ego/investigation network for one selected person."""
    pid = str(person_id)
    H = nx.Graph()
    _add_node(H, pid, "person", _person_display_name(pid))

    def add_relation(u, v, relation):
        if str(u) == str(v):
            return
        H.add_edge(str(u), str(v), relationship=relation)

    connected_people = {}
    if {"caller_person_id", "receiver_person_id"}.issubset(cdr.columns):
        for _, r in cdr.iterrows():
            caller = str(r.get("caller_person_id", ""))
            receiver = str(r.get("receiver_person_id", ""))
            if caller == pid and receiver and receiver != pid:
                connected_people[receiver] = connected_people.get(receiver, 0) + 1
            elif receiver == pid and caller and caller != pid:
                connected_people[caller] = connected_people.get(caller, 0) + 1

    if {"sender_person_id", "receiver_person_id"}.issubset(transactions.columns):
        for _, r in transactions.iterrows():
            sender = str(r.get("sender_person_id", ""))
            receiver = str(r.get("receiver_person_id", ""))
            if sender == pid and receiver and receiver != pid:
                connected_people[receiver] = connected_people.get(receiver, 0) + 1
            elif receiver == pid and sender and sender != pid:
                connected_people[sender] = connected_people.get(sender, 0) + 1

    if pid in G:
        for n in G.neighbors(pid):
            n = str(n)
            if n in persons and n != pid:
                connected_people[n] = connected_people.get(n, 0) + 1

    for other, count in sorted(connected_people.items(), key=lambda x: (-x[1], x[0]))[:max_connected_people]:
        _add_node(H, other, "person", _person_display_name(other))
        add_relation(pid, other, f"PERSON CONNECTION · {count}")

    if {"phone_id", "person_id"}.issubset(phones.columns):
        rows = phones[phones["person_id"].astype(str).eq(pid)].head(max_per_type)
        for _, r in rows.iterrows():
            phone_id = str(r["phone_id"])
            nid = f"PH:{phone_id}"
            _add_node(H, nid, "phone", str(r.get("phone_number", phone_id)))
            add_relation(pid, nid, "PHONE")

    vehicle_ids = []
    if {"vehicle_id", "owner_person_id"}.issubset(vehicles.columns):
        vehicle_ids.extend(vehicles.loc[vehicles["owner_person_id"].astype(str).eq(pid), "vehicle_id"].astype(str).tolist())
    if {"vehicle_id", "person_id"}.issubset(vehicle_events.columns):
        vehicle_ids.extend(vehicle_events.loc[vehicle_events["person_id"].astype(str).eq(pid), "vehicle_id"].astype(str).tolist())
    for vehicle_id in list(dict.fromkeys(vehicle_ids))[:max_per_type]:
        nid = f"VEH:{vehicle_id}"
        _add_node(H, nid, "vehicle", _entity_label("vehicle", vehicle_id))
        add_relation(pid, nid, "VEHICLE")

    if {"account_id", "person_id"}.issubset(bank_accounts.columns):
        rows = bank_accounts[bank_accounts["person_id"].astype(str).eq(pid)].head(max_per_type)
        for _, r in rows.iterrows():
            account_id = str(r["account_id"])
            nid = f"BA:{account_id}"
            _add_node(H, nid, "bank_account", _entity_label("bank_account", account_id))
            add_relation(pid, nid, "BANK ACCOUNT")

    if {"device_id", "person_id"}.issubset(devices.columns):
        rows = devices[devices["person_id"].astype(str).eq(pid)].head(max_per_type)
        for _, r in rows.iterrows():
            device_id = str(r["device_id"])
            nid = f"DEV:{device_id}"
            _add_node(H, nid, "device", _entity_label("device", device_id))
            add_relation(pid, nid, "DEVICE")

    location_ids = []
    if {"person_id", "location_id"}.issubset(locations.columns):
        location_ids.extend(locations.loc[locations["person_id"].astype(str).eq(pid), "location_id"].astype(str).tolist())
    if {"person_id", "location_id"}.issubset(surveillance.columns):
        location_ids.extend(surveillance.loc[surveillance["person_id"].astype(str).eq(pid), "location_id"].astype(str).tolist())
    for location_id in list(dict.fromkeys(location_ids))[:max_per_type]:
        nid = f"LOC:{location_id}"
        _add_node(H, nid, "location", _entity_label("location", location_id))
        add_relation(pid, nid, "LOCATION")

    if {"person_id", "case_id"}.issubset(case_assoc.columns):
        rows = case_assoc[case_assoc["person_id"].astype(str).eq(pid)].head(max_per_type)
        for _, r in rows.iterrows():
            case_id = str(r["case_id"])
            nid = f"CASE:{case_id}"
            _add_node(H, nid, "case", _entity_label("case", case_id))
            add_relation(pid, nid, "CASE")

    if "person_id" in forensic.columns:
        rows = forensic[forensic["person_id"].astype(str).eq(pid)].head(max_per_type)
        evidence_id_col = next((c for c in ["report_id", "fingerprint_id", "evidence_id"] if c in rows.columns), None)
        if evidence_id_col:
            for _, r in rows.iterrows():
                evidence_id = str(r[evidence_id_col])
                nid = f"EVD:{evidence_id}"
                _add_node(H, nid, "evidence", evidence_id)
                add_relation(pid, nid, "EVIDENCE")

    if pid in G:
        for n in G.neighbors(pid):
            attrs = G.nodes[n]
            raw_type = str(attrs.get("type", attrs.get("node_type", attrs.get("entity_type", "")))).lower()
            if raw_type in {"organization", "org", "company"}:
                nid = f"ORG:{n}"
                _add_node(H, nid, "organization", str(attrs.get("name", n)))
                add_relation(pid, nid, "ORGANIZATION")

    return H


def render_individual_investigation_network(person_id):
    """Render the selected person's investigation network with the requested icons."""
    H = build_individual_investigation_network(person_id)
    if H.number_of_nodes() <= 1:
        st.info("No connected investigation records are available for this person.")
        return H

    st.markdown("### Individual Investigation Network")
    st.caption(f"{_person_display_name(person_id)} · Focused multi-source investigation view")

    ICONS = {
        "person": "👤", "phone": "☎", "vehicle": "🚗", "bank_account": "🏦",
        "organization": "🏢", "location": "📍", "case": "📁", "device": "💻", "evidence": "E",
    }
    COLORS = {
        "person": "#2B78B5", "phone": "#4B82C4", "vehicle": "#4E9B51", "bank_account": "#D18A2B",
        "organization": "#8B5FA7", "location": "#C96D43", "case": "#B35B7C", "device": "#3E8F8F", "evidence": "#7C6A50",
    }

    center = str(person_id)
    people = [n for n in H.nodes if H.nodes[n].get("node_type") == "person" and n != center]
    entities = [n for n in H.nodes if n != center and n not in people]

    W, HGT = 1180, 720
    cx, cy = 470, 355
    positions = {center: (cx, cy)}

    if people:
        rx, ry = 190, 145
        for i, n in enumerate(people):
            angle = (2 * np.pi * i / len(people)) - np.pi / 2
            positions[n] = (cx + rx * np.cos(angle), cy + ry * np.sin(angle))

    rings = [[], []]
    for i, n in enumerate(entities):
        rings[min(i // 16, 1)].append(n)
    for ring_idx, nodes in enumerate(rings):
        if not nodes:
            continue
        rx, ry = ((330, 235), (445, 305))[ring_idx]
        count = len(nodes)
        for j, n in enumerate(nodes):
            angle = (2 * np.pi * j / count) - np.pi / 2 + (0.07 * ring_idx)
            positions[n] = (cx + rx * np.cos(angle), cy + ry * np.sin(angle))

    def esc(value):
        return html.escape(str(value), quote=True)

    svg = [f"""<div style=\"width:100%;background:#fff;border:1px solid #e2e5e8;border-radius:12px;overflow:hidden;\">
    <svg viewBox=\"0 0 {W} {HGT}\" width=\"100%\" role=\"img\" aria-label=\"Individual investigation network\" style=\"display:block;background:#fff;font-family:Segoe UI,Arial,sans-serif;\">
      <defs><filter id=\"individualShadow\" x=\"-30%\" y=\"-30%\" width=\"160%\" height=\"160%\"><feDropShadow dx=\"0\" dy=\"2\" stdDeviation=\"3\" flood-opacity=\"0.16\"/></filter></defs>
      <text x=\"590\" y=\"34\" text-anchor=\"middle\" font-size=\"23\" font-weight=\"700\" fill=\"#25313A\">Individual Investigation Network</text>
      <text x=\"590\" y=\"55\" text-anchor=\"middle\" font-size=\"11\" fill=\"#7A858D\">{esc(_person_display_name(center))} · Multi-source evidence map</text>
      <rect x=\"18\" y=\"75\" width=\"1144\" height=\"610\" rx=\"10\" fill=\"#FFFFFF\"/>"""]

    edge_colors = {
        "PHONE": "#6B8FD3", "VEHICLE": "#6FA56F", "BANK ACCOUNT": "#D5A15A", "DEVICE": "#69A6A6",
        "LOCATION": "#D28A67", "CASE": "#BF7894", "EVIDENCE": "#9C8A70", "ORGANIZATION": "#9873AD",
        "PERSON CONNECTION": "#4F78A8",
    }

    for u, v, data in H.edges(data=True):
        if u not in positions or v not in positions:
            continue
        x1, y1 = positions[u]; x2, y2 = positions[v]
        rel = str(data.get("relationship", "RELATED"))
        base = rel.split(" · ")[0]
        edge_color = edge_colors.get(base, "#A5A9AD")
        direct_person = H.nodes[u].get("node_type") == "person" and H.nodes[v].get("node_type") == "person"
        width = 3.0 if direct_person else 1.25
        opacity = 0.78 if direct_person else 0.43
        svg.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{edge_color}" stroke-width="{width}" opacity="{opacity}"/>')

    for node in H.nodes:
        typ = str(H.nodes[node].get("node_type", "evidence"))
        x, y = positions[node]
        is_center = node == center
        is_person = typ == "person"
        r = 34 if is_center else (25 if is_person else 21)
        stroke = COLORS.get(typ, "#7C6A50")
        fill = "#EAF3FB" if is_center else "#FFFFFF"
        icon = ICONS.get(typ, "E")
        label = str(H.nodes[node].get("display_label", node))
        if len(label) > 27:
            label = label[:24] + "…"
        icon_size = 27 if is_center else (22 if is_person else 19)
        label_y = y + r + 16
        svg.append('<g filter="url(#individualShadow)">')
        svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="2.5"/>')
        svg.append(f'<text x="{x:.1f}" y="{y + icon_size * 0.34:.1f}" text-anchor="middle" font-size="{icon_size}px" font-weight="700" fill="{stroke}">{esc(icon)}</text>')
        svg.append('</g>')
        svg.append(f'<text x="{x:.1f}" y="{label_y:.1f}" text-anchor="middle" font-size="{10 if is_center else 8}px" font-weight="{700 if is_center or is_person else 400}" fill="#343A40">{esc(label)}</text>')

    lx, ly = 965, 115
    svg.append(f'<text x="{lx}" y="{ly}" font-size="13" font-weight="700" fill="#34414A">Node Legend</text>')
    legend = [("person", "Person"), ("phone", "Phone"), ("vehicle", "Vehicle"), ("bank_account", "Bank Account"), ("organization", "Organization"), ("location", "Location"), ("case", "Case"), ("device", "Device"), ("evidence", "Evidence")]
    for i, (typ, name) in enumerate(legend):
        yy = ly + 26 + i * 30
        svg.append(f'<circle cx="{lx + 9}" cy="{yy}" r="10" fill="#fff" stroke="{COLORS[typ]}" stroke-width="1.9"/>')
        svg.append(f'<text x="{lx + 9}" y="{yy + 3.7}" text-anchor="middle" font-size="11">{esc(ICONS[typ])}</text>')
        svg.append(f'<text x="{lx + 28}" y="{yy + 4}" font-size="10" fill="#56616A">{esc(name)}</text>')

    svg.append(f'<text x="590" y="670" text-anchor="middle" font-size="9.5" fill="#7A838A">Visible nodes: {H.number_of_nodes()}  •  Relationships: {H.number_of_edges()}  •  Connected persons: {len(people)}</text>')
    svg.append('</svg></div>')
    components.html("".join(svg), height=745, scrolling=False)
    return H

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

    render_xai_panel(selected)

    # Focused visual network for the selected person.
    render_individual_investigation_network(selected)

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
allowed_pages = set(ROLE_PAGES.get(st.session_state.get("role", "Police"), ROLE_PAGES["Police"]))
if page not in allowed_pages:
    st.session_state.page = "Dashboard"
    page = "Dashboard"

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
    render_geospatial_intelligence()
elif page == "Network Explorer":
    render_network()
elif page == "Relationships":
    render_relationships()
elif page == "Timeline":
    render_table_page("Timeline", locations)
elif page == "Evidence":
    render_evidence()
elif page == "Reports":
    render_reports_ai()
elif page == "Help & Support":
    render_help_support()
elif page == "Complaint Box":
    render_complaint_box()
elif page == "Settings":
    render_settings()
else:
    render_dashboard()
