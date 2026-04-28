import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
import hashlib
import secrets
import time
import json
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────────────────────────────────────
DB_PATH = "master_dashboard.db"

def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    conn = get_conn(); c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS master_admin (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        created_by TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        permissions TEXT DEFAULT '{}',
        full_name TEXT DEFAULT '')""")

    c.execute("""CREATE TABLE IF NOT EXISTS share_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL, created_by TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        label TEXT DEFAULT 'Shared Dashboard',
        assigned_users TEXT DEFAULT '[]')""")

    c.execute("""CREATE TABLE IF NOT EXISTS data_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL, data_json TEXT NOT NULL,
        filename TEXT, uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP)""")

    # ── PERSISTENT SESSIONS — survives page refresh ──────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS persistent_sessions (
        session_token TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        username TEXT NOT NULL,
        access_token TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT DEFAULT CURRENT_TIMESTAMP)""")

    # ── VIEW LOG TABLE ── tracks who viewed what and when
    c.execute("""CREATE TABLE IF NOT EXISTS view_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL,
        username TEXT NOT NULL,
        full_name TEXT DEFAULT '',
        viewed_at TEXT DEFAULT CURRENT_TIMESTAMP,
        session_id TEXT DEFAULT '')""")

    # Safe column additions for existing DBs
    for sql in [
        "ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT '{}'",
        "ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT ''",
        "ALTER TABLE share_links ADD COLUMN assigned_users TEXT DEFAULT '[]'",
    ]:
        try: c.execute(sql)
        except: pass

    c.execute("INSERT OR IGNORE INTO master_admin (username, password_hash) VALUES (?,?)",
              ("master", hash_password("master@123")))
    conn.commit(); conn.close()

def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()

# ── Persistent Session CRUD ───────────────────────────────────────────────────
def create_persistent_session(role, username, access_token=""):
    token = secrets.token_urlsafe(32)
    conn = get_conn(); c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT OR REPLACE INTO persistent_sessions
                  (session_token, role, username, access_token, created_at, last_seen)
                  VALUES (?,?,?,?,?,?)""",
              (token, role, username, access_token, now, now))
    conn.commit(); conn.close()
    return token

def load_persistent_session(session_token):
    # Return session dict or None if invalid/expired (7 days).
    if not session_token: return None
    conn = get_conn(); c = conn.cursor()
    c.execute("""SELECT role, username, access_token, created_at
                  FROM persistent_sessions WHERE session_token=?""", (session_token,))
    row = c.fetchone()
    if row:
        # Touch last_seen
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE persistent_sessions SET last_seen=? WHERE session_token=?",
                  (now, session_token))
        conn.commit()
    conn.close()
    if not row: return None
    # Expiry: 7 days
    from datetime import timedelta
    created = datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S")
    if datetime.now() - created > timedelta(days=7):
        delete_persistent_session(session_token)
        return None
    return {"role": row[0], "username": row[1], "access_token": row[2]}

def delete_persistent_session(session_token):
    if not session_token: return
    conn = get_conn(); c = conn.cursor()
    c.execute("DELETE FROM persistent_sessions WHERE session_token=?", (session_token,))
    conn.commit(); conn.close()

# ── Auth ──────────────────────────────────────────────────────────────────────
def verify_master(u, p):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT password_hash FROM master_admin WHERE username=?", (u,))
    row = c.fetchone(); conn.close()
    return bool(row and row[0] == hash_password(p))

def verify_user(u, p):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=? AND is_active=1", (u,))
    row = c.fetchone(); conn.close()
    return bool(row and row[0] == hash_password(p))

def get_user_info(username):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT id,username,full_name,permissions FROM users WHERE username=? AND is_active=1",(username,))
    row = c.fetchone(); conn.close()
    if row:
        return {"id":row[0],"username":row[1],"full_name":row[2],
                "permissions":json.loads(row[3] or '{}')}
    return None

# ── Users ─────────────────────────────────────────────────────────────────────
def create_user(username, password, created_by, full_name="", permissions=None):
    conn = get_conn(); c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username,password_hash,created_by,full_name,permissions) VALUES(?,?,?,?,?)",
                  (username, hash_password(password), created_by, full_name, json.dumps(permissions or {})))
        conn.commit(); conn.close(); return True, "User created!"
    except sqlite3.IntegrityError:
        conn.close(); return False, "Username already exists!"

def update_user_permissions(user_id, permissions):
    conn = get_conn(); c = conn.cursor()
    c.execute("UPDATE users SET permissions=? WHERE id=?", (json.dumps(permissions), user_id))
    conn.commit(); conn.close()

def get_all_users():
    conn = get_conn()
    df = pd.read_sql("SELECT id,username,full_name,created_by,created_at,is_active,permissions FROM users", conn)
    conn.close(); return df

def delete_user(uid):
    conn = get_conn(); c = conn.cursor()
    c.execute("UPDATE users SET is_active=0 WHERE id=?", (uid,)); conn.commit(); conn.close()

# ── Share Links ───────────────────────────────────────────────────────────────
def generate_share_link(created_by, label="Shared Dashboard", assigned_users=None):
    token = secrets.token_urlsafe(16)
    conn = get_conn(); c = conn.cursor()
    c.execute("INSERT INTO share_links (token,created_by,label,assigned_users) VALUES(?,?,?,?)",
              (token, created_by, label, json.dumps(assigned_users or [])))
    conn.commit(); conn.close(); return token

def get_share_links():
    conn = get_conn()
    df = pd.read_sql("SELECT * FROM share_links WHERE is_active=1", conn)
    conn.close(); return df

def update_link_assigned_users(token, users):
    conn = get_conn(); c = conn.cursor()
    c.execute("UPDATE share_links SET assigned_users=? WHERE token=?", (json.dumps(users), token))
    conn.commit(); conn.close()

def deactivate_link(token):
    conn = get_conn(); c = conn.cursor()
    c.execute("UPDATE share_links SET is_active=0 WHERE token=?", (token,)); conn.commit(); conn.close()

def verify_token(token):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT id FROM share_links WHERE token=? AND is_active=1", (token,))
    row = c.fetchone(); conn.close(); return row is not None

# ── Data Sessions ─────────────────────────────────────────────────────────────
def save_data_for_token(token, df, filename):
    conn = get_conn(); c = conn.cursor()
    c.execute("DELETE FROM data_sessions WHERE token=?", (token,))
    c.execute("INSERT INTO data_sessions (token,data_json,filename) VALUES(?,?,?)",
              (token, df.to_json(orient='records', date_format='iso'), filename))
    conn.commit(); conn.close()

DATETIME_COLS = ['Issue diss. Date','Closure Month','Cut off Date / Closure Date',
                 'Milestone Target Date','Closure Month - Plan']

def _reparse_dt(df):
    for col in DATETIME_COLS:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors='coerce')
    return df

def load_data_for_token(token):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT data_json,filename FROM data_sessions WHERE token=? ORDER BY id DESC LIMIT 1",(token,))
    row = c.fetchone(); conn.close()
    if row:
        df = pd.read_json(row[0], orient='records')
        return _reparse_dt(df), row[1]
    return None, None

# ── View Tracking ─────────────────────────────────────────────────────────────
def log_view(token, username, full_name, session_id=""):
    """Record that a user viewed this dashboard link."""
    conn = get_conn(); c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO view_log (token,username,full_name,viewed_at,session_id) VALUES(?,?,?,?,?)",
              (token, username, full_name, now, session_id))
    conn.commit(); conn.close()

def get_view_log(token):
    """Get all view records for a token, latest first."""
    conn = get_conn()
    df = pd.read_sql(
        "SELECT username,full_name,viewed_at FROM view_log WHERE token=? ORDER BY viewed_at DESC",
        conn, params=(token,))
    conn.close(); return df

def get_unique_viewers(token):
    """Get unique viewers with their first and last seen time."""
    conn = get_conn()
    df = pd.read_sql("""
        SELECT username, full_name,
               COUNT(*) as total_views,
               MIN(viewed_at) as first_seen,
               MAX(viewed_at) as last_seen
        FROM view_log WHERE token=?
        GROUP BY username ORDER BY last_seen DESC
    """, conn, params=(token,))
    conn.close(); return df

def get_unseen_users(token, assigned_users):
    """Which assigned users have NEVER viewed this link."""
    if not assigned_users: return []
    viewers = get_unique_viewers(token)
    seen = set(viewers['username'].tolist()) if not viewers.empty else set()
    return [u for u in assigned_users if u not in seen]

# ── Permissions helper ────────────────────────────────────────────────────────
def apply_permissions(df, permissions):
    if not permissions: return df
    fdf = df.copy()
    if permissions.get("continents"):  fdf = fdf[fdf["Continent"].isin(permissions["continents"])]
    if permissions.get("countries"):   fdf = fdf[fdf["Country"].isin(permissions["countries"])]
    if permissions.get("departments"): fdf = fdf[fdf["Department"].isin(permissions["departments"])]
    if permissions.get("hp_categories"):fdf = fdf[fdf["HP category"].isin(permissions["hp_categories"])]
    if permissions.get("milestones"):  fdf = fdf[fdf["Current Milestone"].isin(permissions["milestones"])]
    if permissions.get("issue_types") and "Issue Type" in fdf.columns:
        fdf = fdf[fdf["Issue Type"].isin(permissions["issue_types"])]
    return fdf

# ─────────────────────────────────────────────────────────────────────────────
#  COLOUR MAPS
# ─────────────────────────────────────────────────────────────────────────────
CONT_COLORS = {
    'Asia':   ['#00E5FF','#0891B2','#38BDF8','#7DD3FC'],
    'Europe': ['#FFD700','#F59E0B','#FCD34D','#FDE68A'],
    'America':['#00FF9D','#16A34A','#4ADE80','#86EFAC'],
    'Africa': ['#FF6B35','#EA580C','#FB923C','#FDBA74'],
    'Oceania':['#FF4DFF','#DB2777','#F472B6','#FBCFE8'],
    'Unknown':['#94A3B8','#64748B','#CBD5E1','#E2E8F0'],
}
MILE_COL = {
    'Implemented':'#16A34A','Field Information Awaited':'#2563EB',
    'Field information awaited':'#2563EB','RCA in CFT - Under Study':'#D97706',
    'Design Review - Feasibility Study':'#7C3AED',
    'Supplier Action - Actions awaited':'#EA580C','Under Implementation':'#0891B2',
    'RCA in CFT - Failed Part Analysis':'#DC2626','Failed part awaited':'#DB2777',
    'Material Availability':'#65A30D','TWS/ IPE Project':'#1E3A8A',
    'TWS/ IPE Project - Testing/ Validation/ Fitment':'#3B82F6','Closed':'#6B7280',
}
DEPT_COL = {
    'CFT':'#2563EB','Closed':'#16A34A','Service':'#D97706','R&D':'#7C3AED',
    'IQC':'#EA580C','Purchase':'#DB2777','Business Excellence':'#0891B2',
    'Engine Assembly':'#DC2626',
}
ISO3 = {
    'Thailand':'THA','Nepal':'NPL','Brazil':'BRA','Bangladesh':'BGD','USA':'USA',
    'Portugal':'PRT','Myanmar':'MMR','Poland':'POL','Denmark':'DNK','Mexico':'MEX',
    'UK':'GBR','Turkey':'TUR','FIJI':'FJI','Afghanistan':'AFG','Arjentina':'ARG',
    'Czech Republic':'CZE','Finland':'FIN','Finlanad':'FIN','Moldova':'MDA',
    'Belaruse':'BLR','Romania':'ROU','Algeria':'DZA','Morraco':'MAR','Tunisia':'TUN',
    'Tanzania':'TZA','Nepal Solis':'NPL','Vietnam':'VNM','Keneya':'KEN',
    'South Africa':'ZAF','Australia':'AUS','ITLAY':'ITA','Netherlands':'NLD',
}

def _expand_countries(data):
    rows = []
    for _, row in data.iterrows():
        if pd.isna(row.get('Country')): rows.append(row.to_dict()); continue
        parts = str(row['Country']).replace(' and ',',').replace('&',',').split(',')
        seen = set()
        for p in parts:
            c = p.strip()
            if c and c not in seen:
                seen.add(c); d = row.to_dict(); d['Country'] = c; rows.append(d)
    return pd.DataFrame(rows)

def process_excel(file):
    data = pd.read_excel(file)
    if 'HP category' in data.columns:
        data['HP category'] = data['HP category'].str.strip()
        data.loc[data['HP category']=='30-60 HP','HP category'] = '30 - 60 HP'
    if 'Current Milestone' in data.columns:
        data['Current Milestone'] = data['Current Milestone'].fillna('').str.strip()
        data.loc[data['Current Milestone']=='Field information awaited',
                 'Current Milestone'] = 'Field Information Awaited'
    for col in DATETIME_COLS:
        if col in data.columns: data[col] = pd.to_datetime(data[col], errors='coerce')
    if 'Aging' in data.columns:
        data['Aging'] = pd.to_numeric(data['Aging'], errors='coerce')
        data['Aging'] = data['Aging'].where(data['Aging'] < 500)
    data = _expand_countries(data)
    data['ISO3'] = data['Country'].map(ISO3)
    return data

# ─────────────────────────────────────────────────────────────────────────────
#  PAGE CONFIG & CSS
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="Issues Intelligence", page_icon="📊",
                   layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Space+Grotesk:wght@300;400;500;600&family=JetBrains+Mono:wght@400;600&display=swap');
*{font-family:'Space Grotesk',sans-serif;}
h1,h2,h3{font-family:'Orbitron',sans-serif;font-weight:700;letter-spacing:2px;}
.stApp{background:#030712;background-image:linear-gradient(rgba(0,229,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,0.03) 1px,transparent 1px);background-size:40px 40px;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#060d1a 0%,#030712 100%)!important;border-right:1px solid rgba(0,229,255,0.15)!important;}
.master-badge{background:linear-gradient(135deg,#FFD700,#FF8C00);color:#000;font-weight:900;padding:5px 14px;border-radius:20px;font-size:11px;letter-spacing:2.5px;display:inline-block;margin-bottom:8px;box-shadow:0 0 18px rgba(255,215,0,0.4);font-family:'Orbitron',sans-serif;}
.user-badge{background:linear-gradient(135deg,#00E5FF,#0066CC);color:#000;font-weight:900;padding:5px 14px;border-radius:20px;font-size:11px;letter-spacing:2.5px;display:inline-block;margin-bottom:8px;box-shadow:0 0 18px rgba(0,229,255,0.35);font-family:'Orbitron',sans-serif;}
.stat-card{background:linear-gradient(135deg,#060d1a 0%,#0a1628 100%);border:1px solid rgba(0,229,255,0.2);border-radius:14px;padding:22px 14px;text-align:center;margin:4px 0;transition:all 0.35s;position:relative;overflow:hidden;}
.stat-card::before{content:'';position:absolute;inset:0;background:radial-gradient(circle at 50% 0%,rgba(0,229,255,0.06),transparent 70%);pointer-events:none;}
.stat-card:hover{border-color:rgba(0,229,255,0.7);transform:translateY(-4px);box-shadow:0 0 32px rgba(0,229,255,0.2),0 12px 40px rgba(0,0,0,0.5);}
.stat-number{font-size:34px;font-weight:900;font-family:'Orbitron',sans-serif;line-height:1;}
.stat-label{font-size:10px;color:#4a6a8a;letter-spacing:2px;text-transform:uppercase;margin-top:6px;font-family:'JetBrains Mono',monospace;}
.link-box{background:#060d1a;border:1px dashed rgba(0,229,255,0.5);border-radius:8px;padding:14px 18px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#00E5FF;word-break:break-all;margin:8px 0;}
.perm-tag{display:inline-block;background:rgba(0,229,255,0.1);border:1px solid rgba(0,229,255,0.3);color:#00E5FF;border-radius:20px;padding:2px 10px;font-size:11px;margin:2px;font-family:'JetBrains Mono',monospace;}
.perm-full{display:inline-block;background:rgba(74,222,128,0.1);border:1px solid rgba(74,222,128,0.4);color:#4ADE80;border-radius:20px;padding:2px 10px;font-size:11px;font-family:'JetBrains Mono',monospace;}
.seen-tag{display:inline-block;background:rgba(74,222,128,0.12);border:1px solid rgba(74,222,128,0.4);color:#4ADE80;border-radius:20px;padding:3px 12px;font-size:11px;margin:2px;font-family:'JetBrains Mono',monospace;}
.unseen-tag{display:inline-block;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.4);color:#EF4444;border-radius:20px;padding:3px 12px;font-size:11px;margin:2px;font-family:'JetBrains Mono',monospace;}
.viewer-card{background:linear-gradient(135deg,#060d1a,#0a1628);border:1px solid rgba(0,229,255,0.12);border-radius:10px;padding:12px 16px;margin:6px 0;}
.user-card{background:linear-gradient(135deg,#060d1a,#0a1628);border:1px solid rgba(0,229,255,0.15);border-radius:12px;padding:14px 18px;margin:8px 0;}
.glow-title{font-family:'Orbitron',sans-serif;font-size:26px;font-weight:900;color:#00E5FF;text-shadow:0 0 20px rgba(0,229,255,0.6),0 0 60px rgba(0,229,255,0.2);letter-spacing:3px;margin-bottom:4px;}
.sub-title{font-family:'JetBrains Mono',monospace;font-size:11px;color:#4a6a8a;letter-spacing:4px;text-transform:uppercase;}
.section-header{background:linear-gradient(90deg,rgba(0,229,255,0.08),transparent);border-left:3px solid #00E5FF;padding:10px 16px;border-radius:0 8px 8px 0;margin:20px 0 12px;font-family:'Orbitron',sans-serif;font-size:12px;color:#94c7e0;letter-spacing:2px;}
.stTextInput input{background:#060d1a!important;border:1px solid rgba(0,229,255,0.2)!important;color:white!important;border-radius:8px!important;}
.stTextInput input:focus{border-color:#00E5FF!important;box-shadow:0 0 0 3px rgba(0,229,255,0.12)!important;}
.stButton>button{width:100%;background:linear-gradient(135deg,#0f2a4a,#0066CC)!important;color:white!important;border:1px solid rgba(0,229,255,0.25)!important;border-radius:8px!important;padding:12px!important;font-weight:700!important;font-family:'Orbitron',sans-serif!important;letter-spacing:1.5px!important;font-size:13px!important;transition:all 0.3s!important;}
.stButton>button:hover{background:linear-gradient(135deg,#1a3a6a,#0088FF)!important;transform:translateY(-1px)!important;box-shadow:0 6px 24px rgba(0,102,204,0.5)!important;}
.stTabs [data-baseweb="tab-list"]{background:rgba(6,13,26,0.8);border-radius:12px;padding:4px;border:1px solid rgba(0,229,255,0.1);}
.stTabs [data-baseweb="tab"]{color:#4a6a8a!important;border-radius:8px!important;font-family:'Orbitron',sans-serif!important;font-size:11px!important;letter-spacing:1px!important;}
.stTabs [aria-selected="true"]{background:linear-gradient(135deg,#0f2a4a,#0a1e38)!important;color:#00E5FF!important;box-shadow:0 0 16px rgba(0,229,255,0.2)!important;}
div[data-testid="metric-container"]{background:#060d1a;border:1px solid rgba(0,229,255,0.15);border-radius:10px;padding:12px;}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
#  SESSION STATE  — persistent across refresh via ?sid= URL param
# ─────────────────────────────────────────────────────────────────────────────
init_db()
for k, v in {'role':None,'username':None,'access_token':None,'session_id':None,
             '_session_restored':False}.items():
    if k not in st.session_state: st.session_state[k] = v

params    = st.query_params
url_token = params.get("token", None)
sid_param = params.get("sid",   None)

# ── Restore session from ?sid= on every page load (handles F5 refresh) ──────
if not st.session_state.role and sid_param:
    _sess = load_persistent_session(sid_param)
    if _sess:
        st.session_state.role         = _sess["role"]
        st.session_state.username     = _sess["username"]
        st.session_state.access_token = _sess["access_token"]
        st.session_state._session_restored = True

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _perm_tags(perms):
    if not perms: return '<span class="perm-full">✅ Full Access</span>'
    icons = {"continents":"🌍","countries":"📍","departments":"🏢",
             "hp_categories":"⚙️","milestones":"🎯","issue_types":"🔧"}
    tags = []
    for k, vals in perms.items():
        for v in (vals or []):
            tags.append(f'<span class="perm-tag">{icons.get(k,"•")} {v}</span>')
    return " ".join(tags) if tags else '<span class="perm-full">✅ Full Access</span>'

def _get_base_url():
    try:
        host = st.get_option("browser.serverAddress") or "localhost"
        port = st.get_option("browser.serverPort") or 8501
        return f"http://{host}:{port}"
    except:
        return "http://localhost:8501"

def _perm_selector(prefix, df_ref, existing=None):
    """Render permission multiselects, return permissions dict."""
    existing = existing or {}
    access = st.radio("Access Level",
        ["🌐 Full Access (All Data)", "🔒 Restricted Access (Custom Filters)"],
        key=f"{prefix}_atype", index=0 if not existing else 1)
    if "Full Access" in access: return {}
    perms = {}
    if 'Continent' in df_ref.columns:
        s = st.multiselect("Allowed Continents", sorted(df_ref['Continent'].dropna().unique()),
                           default=existing.get("continents",[]), key=f"{prefix}_cont")
        if s: perms["continents"] = s
    if 'Country' in df_ref.columns:
        s = st.multiselect("Allowed Countries", sorted(df_ref['Country'].dropna().unique()),
                           default=existing.get("countries",[]), key=f"{prefix}_cntry")
        if s: perms["countries"] = s
    if 'Department' in df_ref.columns:
        s = st.multiselect("Allowed Departments", sorted(df_ref['Department'].dropna().unique()),
                           default=existing.get("departments",[]), key=f"{prefix}_dept")
        if s: perms["departments"] = s
    if 'HP category' in df_ref.columns:
        s = st.multiselect("Allowed HP Categories", sorted(df_ref['HP category'].dropna().unique()),
                           default=existing.get("hp_categories",[]), key=f"{prefix}_hp")
        if s: perms["hp_categories"] = s
    if 'Current Milestone' in df_ref.columns:
        s = st.multiselect("Allowed Milestones",
                           sorted(df_ref['Current Milestone'].replace('',pd.NA).dropna().unique()),
                           default=existing.get("milestones",[]), key=f"{prefix}_mile")
        if s: perms["milestones"] = s
    if 'Issue Type' in df_ref.columns:
        s = st.multiselect("Allowed Issue Types", sorted(df_ref['Issue Type'].dropna().unique()),
                           default=existing.get("issue_types",[]), key=f"{prefix}_itype")
        if s: perms["issue_types"] = s
    return perms

# ─────────────────────────────────────────────────────────────────────────────
#  3D CHART HELPERS  ← titlefont BUG FIXED (use title=dict(...) for scene axes)
# ─────────────────────────────────────────────────────────────────────────────
def _sa(label):
    """Build a correct plotly scene-axis dict — NO titlefont key."""
    return dict(
        title=dict(text=label, font=dict(color='#00E5FF', size=11, family='Space Grotesk')),
        tickfont=dict(color='#4a6a8a', size=9, family='Space Grotesk'),
        gridcolor='rgba(0,229,255,0.08)',
        backgroundcolor='rgba(6,13,26,0.9)',
        showbackground=True,
    )

def _3d_layout(title, h=520):
    return dict(
        template='plotly_dark',
        paper_bgcolor='rgba(3,7,18,0)',
        font=dict(family='Space Grotesk', color='#94a3b8'),
        margin=dict(l=0,r=0,t=40,b=0),
        height=h,
        title=dict(text=title, font=dict(family='Orbitron', color='#00E5FF', size=13)),
        scene=dict(
            bgcolor='rgba(6,13,26,0.95)',
            xaxis=_sa('X'), yaxis=_sa('Y'), zaxis=_sa('Z'),
        )
    )

def make_3d_scatter(fdf):
    sc = fdf.copy()
    sc['Month_num'] = sc['Issue diss. Date'].dt.month.fillna(0)
    sc['Fail_num']  = (pd.to_numeric(sc['No of Failure'].astype(str).str.extract(r'(\d+)')[0],
                                      errors='coerce') if 'No of Failure' in sc.columns else np.nan)
    sc = sc.dropna(subset=['Aging','Month_num'])
    if sc.empty: return None
    sc['Cont'] = sc['Continent'].fillna('Unknown')
    fig = go.Figure()
    for cont in sc['Cont'].unique():
        sub   = sc[sc['Cont']==cont]
        color = CONT_COLORS.get(cont, CONT_COLORS['Unknown'])[0]
        fig.add_trace(go.Scatter3d(
            x=sub['Aging'], y=sub['Month_num'],
            z=sub['Fail_num'].fillna(1),
            mode='markers', name=cont,
            marker=dict(size=5, color=color, opacity=0.82,
                        line=dict(width=0.4, color='rgba(255,255,255,0.15)')),
            text=sub.get('Country',''),
            hovertemplate='<b>%{text}</b><br>Aging: %{x}d<br>Month: %{y}<br>Failures: %{z}<extra></extra>',
        ))
    L = _3d_layout('3D Scatter — Aging × Issue Month × Failures', 540)
    L['scene']['xaxis'] = _sa('Aging (Days)')
    L['scene']['yaxis'] = _sa('Issue Month')
    L['scene']['zaxis'] = _sa('Failures')
    fig.update_layout(**L)
    return fig

def make_3d_surface(fdf):
    sub = fdf[fdf['Current Milestone'].str.strip()!=''].copy()
    if sub.empty: return None
    pivot = (sub.groupby(['Continent','Current Milestone'])['Ser. No']
               .count().reset_index().rename(columns={'Ser. No':'Count'}))
    conts  = sorted(pivot['Continent'].dropna().unique())
    miles  = sorted(pivot['Current Milestone'].unique())
    Z = np.array([[
        int(pivot[(pivot['Continent']==c)&(pivot['Current Milestone']==m)]['Count'].values[0])
        if len(pivot[(pivot['Continent']==c)&(pivot['Current Milestone']==m)]) else 0
        for c in conts] for m in miles], dtype=float)
    fig = go.Figure(data=[go.Surface(
        z=Z, x=list(range(len(conts))), y=list(range(len(miles))),
        colorscale=[[0,'#030712'],[0.2,'#0a1e38'],[0.5,'#0066CC'],[0.8,'#00E5FF'],[1,'#FFD700']],
        opacity=0.92,
        contours=dict(z=dict(show=True, usecolormap=True, project_z=True, width=1)),
        hovertemplate='Continent: %{x}<br>Milestone: %{y}<br>Issues: %{z}<extra></extra>',
    )])
    L = _3d_layout('3D Surface — Continent × Milestone × Issue Count', 560)
    L['scene']['xaxis'] = {**_sa('Continent'), 'tickvals':list(range(len(conts))), 'ticktext':conts}
    L['scene']['yaxis'] = {**_sa('Milestone'), 'tickvals':list(range(len(miles))), 'ticktext':[m[:18] for m in miles]}
    L['scene']['zaxis'] = _sa('Issue Count')
    fig.update_layout(**L)
    return fig

def make_3d_ribbon(fdf):
    ts = fdf.dropna(subset=['Issue diss. Date']).copy()
    ts['Week'] = ts['Issue diss. Date'].dt.to_period('W').dt.start_time
    ts['Cont'] = ts['Continent'].fillna('Unknown')
    grp = (ts.groupby(['Week','Cont'])['Ser. No'].count().reset_index()
             .rename(columns={'Ser. No':'Count'}))
    if grp.empty: return None
    conts = sorted(grp['Cont'].unique())
    fig   = go.Figure()
    for i, cont in enumerate(conts):
        sub   = grp[grp['Cont']==cont].sort_values('Week')
        color = CONT_COLORS.get(cont, CONT_COLORS['Unknown'])[0]
        fig.add_trace(go.Scatter3d(
            x=sub['Week'].astype(str), y=[i]*len(sub), z=sub['Count'],
            mode='lines+markers', name=cont,
            line=dict(color=color, width=5),
            marker=dict(size=4, color=color, opacity=0.8),
            hovertemplate=f'<b>{cont}</b><br>Week: %{{x}}<br>Issues: %{{z}}<extra></extra>',
        ))
    L = _3d_layout('3D Ribbon — Weekly Issues by Continent', 520)
    L['scene']['xaxis'] = _sa('Week')
    L['scene']['yaxis'] = {**_sa('Continent'), 'tickvals':list(range(len(conts))), 'ticktext':conts}
    L['scene']['zaxis'] = _sa('Issues')
    fig.update_layout(**L)
    return fig

def make_3d_bubble(fdf):
    sub = fdf.dropna(subset=['Aging','Department','HP category']).copy()
    if sub.empty: return None
    agg = (sub.groupby(['Department','HP category'])
              .agg(Avg_Aging=('Aging','mean'), Count=('Ser. No','count')).reset_index())
    agg['Avg_Aging'] = agg['Avg_Aging'].round(1)
    depts   = sorted(agg['Department'].unique())
    hp_cats = sorted(agg['HP category'].unique())
    agg['x'] = agg['Department'].map({d:i for i,d in enumerate(depts)})
    agg['y'] = agg['HP category'].map({h:i for i,h in enumerate(hp_cats)})
    fig = go.Figure(data=[go.Scatter3d(
        x=agg['x'], y=agg['y'], z=agg['Avg_Aging'],
        mode='markers',
        marker=dict(size=agg['Count'].clip(3,30), color=agg['Avg_Aging'],
                    colorscale='RdYlGn_r', opacity=0.85,
                    colorbar=dict(title='Avg Aging', thickness=12, len=0.5),
                    line=dict(width=0.5, color='rgba(255,255,255,0.2)')),
        text=agg['Department']+' / '+agg['HP category'],
        customdata=np.stack([agg['Count'],agg['Avg_Aging']], axis=-1),
        hovertemplate='<b>%{text}</b><br>Avg Aging: %{customdata[1]}d<br>Count: %{customdata[0]}<extra></extra>',
    )])
    L = _3d_layout('3D Bubble — Dept × HP Category × Avg Aging', 520)
    L['scene']['xaxis'] = {**_sa('Department'), 'tickvals':list(range(len(depts))), 'ticktext':depts}
    L['scene']['yaxis'] = {**_sa('HP Category'), 'tickvals':list(range(len(hp_cats))), 'ticktext':hp_cats}
    L['scene']['zaxis'] = _sa('Avg Aging (Days)')
    fig.update_layout(**L)
    return fig

# ─────────────────────────────────────────────────────────────────────────────
#  MASTER LOGIN
# ─────────────────────────────────────────────────────────────────────────────
def show_master_login():
    st.markdown("""
    <div style='text-align:center;padding:50px 0 24px;'>
        <div style='font-size:52px;margin-bottom:12px;'>🔐</div>
        <div class='glow-title'>MASTER CONTROL</div>
        <div class='sub-title'>Issues Intelligence System</div>
    </div>""", unsafe_allow_html=True)
    c1,c2,c3 = st.columns([1,1.2,1])
    with c2:
        st.markdown("""<div style="background:linear-gradient(135deg,#060d1a,#030712);
            border:1px solid rgba(255,180,0,0.35);border-radius:18px;padding:36px;">""",
            unsafe_allow_html=True)
        st.markdown('<div class="master-badge">⚡ MASTER ACCESS</div>', unsafe_allow_html=True)
        u = st.text_input("Master Username", placeholder="master", key="m_u")
        p = st.text_input("Password", type="password", key="m_p")
        if st.button("🔓 MASTER LOGIN"):
            if verify_master(u, p):
                st.session_state.role='master'; st.session_state.username=u
                _sid = create_persistent_session('master', u, '')
                st.query_params['sid'] = _sid
                st.success("✅ Access granted!"); time.sleep(0.4); st.rerun()
            else: st.error("❌ Invalid credentials!")
        st.markdown("---")
        st.markdown('<p style="color:#4a6a8a;font-size:11px;text-align:center;font-family:JetBrains Mono,monospace;">Default: master / master@123</p>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
#  EMPLOYEE LOGIN
# ─────────────────────────────────────────────────────────────────────────────
def show_employee_login(token):
    if not verify_token(token):
        st.error("❌ Invalid or expired link."); return
    st.markdown("""
    <div style='text-align:center;padding:50px 0 24px;'>
        <div style='font-size:52px;margin-bottom:12px;'>📊</div>
        <div class='glow-title'>ISSUES DASHBOARD</div>
        <div class='sub-title'>Employee Access Portal</div>
    </div>""", unsafe_allow_html=True)
    c1,c2,c3 = st.columns([1,1.2,1])
    with c2:
        st.markdown("""<div style="background:linear-gradient(135deg,#060d1a,#030712);
            border:1px solid rgba(0,229,255,0.25);border-radius:18px;padding:36px;">""",
            unsafe_allow_html=True)
        st.markdown('<div class="user-badge">👤 EMPLOYEE LOGIN</div>', unsafe_allow_html=True)
        u = st.text_input("Username", key="e_u")
        p = st.text_input("Password", type="password", key="e_p")
        if st.button("🚀 LOGIN"):
            if verify_user(u, p):
                st.session_state.role='user'; st.session_state.username=u
                st.session_state.access_token=token
                st.session_state.session_id=secrets.token_hex(8)
                _sid = create_persistent_session('user', u, token)
                _new_params = dict(st.query_params)
                _new_params['sid'] = _sid
                st.query_params.update(_new_params)
                st.success("✅ Access granted!"); time.sleep(0.4); st.rerun()
            else: st.error("❌ Invalid credentials.")
        st.markdown('</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
#  MASTER DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
def show_master_dashboard():
    with st.sidebar:
        st.markdown('<div class="master-badge">⚡ MASTER</div>', unsafe_allow_html=True)
        st.markdown(f"**{st.session_state.username}**")
        st.markdown("---")
        page = st.radio("Navigation", [
            "📤 Upload & Share",
            "👥 User Management",
            "🔗 Manage Links",
            "📊 View Dashboard"
        ], key="master_nav")
        st.markdown("---")
        if st.button("🚪 Logout"):
            delete_persistent_session(st.query_params.get('sid',''))
            st.query_params.clear()
            for k in ['role','username','access_token','_session_restored']: st.session_state[k]=None
            st.rerun()

    # ── 1. Upload & Share ──────────────────────────────────────────────────
    if page == "📤 Upload & Share":
        st.markdown("# 📤 Upload Data & Generate Share Link")
        c1,c2 = st.columns([1.5,1])
        with c1:
            st.markdown("### Step 1: Upload Excel")
            up = st.file_uploader("Excel file (.xlsx)", type=["xlsx","xls"])
            if up:
                try:
                    df = process_excel(up)
                    st.success(f"✅ {up.name} — {len(df)} rows, {len(df.columns)} cols")
                    st.session_state['master_df']  = df
                    st.session_state['master_fn']  = up.name
                    with st.expander("Preview"):
                        st.dataframe(df.head(), use_container_width=True)
                except Exception as e:
                    st.error(f"Error: {e}")
        with c2:
            st.markdown("### Step 2: Generate Link")
            lbl = st.text_input("Link Label", value="Employee Dashboard", key="ll")
            users_df = get_all_users()
            active_u = users_df[users_df['is_active']==1]['username'].tolist() if not users_df.empty else []
            assigned = st.multiselect("Assign to Users", active_u, key="gen_assign",
                                       help="Which employees will use this link")
            if st.button("🔗 Generate Link"):
                if 'master_df' not in st.session_state:
                    st.warning("⚠️ Pehle Excel upload karo!")
                else:
                    tok = generate_share_link(st.session_state.username, lbl, assigned)
                    save_data_for_token(tok, st.session_state['master_df'], st.session_state['master_fn'])
                    url = f"{_get_base_url()}/?token={tok}"
                    st.success("✅ Link generated!")
                    st.markdown(f'<div class="link-box">🔗 {url}</div>', unsafe_allow_html=True)
                    st.code(url, language=None)

    # ── 2. User Management ─────────────────────────────────────────────────
    elif page == "👥 User Management":
        st.markdown("# 👥 Employee User Management")
        # Load ref data for permission options
        lks = get_share_links()
        df_ref = pd.DataFrame()
        if not lks.empty:
            df_ref, _ = load_data_for_token(lks.iloc[0]['token'])
            if df_ref is None: df_ref = pd.DataFrame()

        t_create, t_list = st.tabs(["➕ Create Employee", "📋 All Employees"])

        with t_create:
            cl1,cl2 = st.columns([1,1.2])
            with cl1:
                st.markdown("### Basic Info")
                with st.form("cuf"):
                    fn   = st.text_input("Full Name",  placeholder="Amit Kumar")
                    un   = st.text_input("Username",   placeholder="amit.kumar")
                    pw   = st.text_input("Password",   type="password")
                    pw2  = st.text_input("Confirm Password", type="password")
                    sub  = st.form_submit_button("✅ Create Employee")
            with cl2:
                st.markdown("### Data Permissions")
                if df_ref.empty:
                    st.info("Upload data first to set permissions."); new_perms={}
                else:
                    new_perms = _perm_selector("nu", df_ref)
            if sub:
                if not un or not pw:
                    st.error("Username & password required!")
                elif pw != pw2:
                    st.error("Passwords don't match!")
                elif len(pw)<6:
                    st.error("Min 6 characters!")
                else:
                    ok,msg = create_user(un,pw,st.session_state.username,fn,new_perms)
                    if ok:
                        st.success(f"✅ Created: {fn or un}")
                        st.info(f"**Username:** `{un}`  \n**Password:** `{pw}`")
                    else:
                        st.error(f"❌ {msg}")

        with t_list:
            users_df = get_all_users()
            if users_df.empty:
                st.info("No users yet.")
            else:
                active = users_df[users_df['is_active']==1]
                st.caption(f"Active employees: **{len(active)}**")
                for _, row in active.iterrows():
                    perms   = json.loads(row.get('permissions','{}') or '{}')
                    nm      = row['full_name'] if row.get('full_name') else row['username']
                    with st.expander(f"👤  {nm}  •  @{row['username']}"):
                        ex1,ex2 = st.columns([1.4,1])
                        with ex1:
                            st.markdown(f"""
                            <div class='user-card'>
                                <span style='color:#00E5FF;font-family:Orbitron,sans-serif;font-size:13px;'>{nm}</span><br>
                                <span style='color:#4a6a8a;font-size:11px;font-family:JetBrains Mono,monospace;'>@{row['username']} &nbsp;•&nbsp; ID #{row['id']}</span><br>
                                <span style='color:#64748b;font-size:11px;'>Created: {str(row['created_at'])[:10]}</span>
                                <div style='margin-top:10px;'>{_perm_tags(perms)}</div>
                            </div>""", unsafe_allow_html=True)
                        with ex2:
                            if not df_ref.empty:
                                with st.form(f"ep_{row['id']}"):
                                    st.markdown("**Update Permissions**")
                                    up = _perm_selector(f"e{row['id']}", df_ref, perms)
                                    if st.form_submit_button("💾 Save"):
                                        update_user_permissions(row['id'], up)
                                        st.success("Saved!"); st.rerun()
                            if st.button(f"🗑️ Disable", key=f"du_{row['id']}"):
                                delete_user(row['id']); st.rerun()

    # ── 3. Manage Links ────────────────────────────────────────────────────
    elif page == "🔗 Manage Links":
        st.markdown("# 🔗 Manage Links")
        st.markdown("Link ke saath kaun assigned hai, kaun dekh chuka hai, sab yahan dikta hai.")
        lks = get_share_links()
        if lks.empty:
            st.info("Koi active link nahi hai."); return
        users_df = get_all_users()

        st.markdown(f"**Total active links: {len(lks)}**")

        for _, row in lks.iterrows():
            url = f"{_get_base_url()}/?token={row['token']}"
            assigned = json.loads(row.get('assigned_users','[]') or '[]')
            viewers  = get_unique_viewers(row['token'])
            unseen   = get_unseen_users(row['token'], assigned)
            seen_cnt = len(viewers) if not viewers.empty else 0
            total_assigned = len(assigned)

            with st.expander(
                f"🔗  {row['label']}  •  {row['created_at'][:10]}  •  "
                f"👁 {seen_cnt} viewed  •  📌 {total_assigned} assigned"
            ):
                tab_info, tab_viewers, tab_assigned, tab_data = st.tabs([
                    "📋 Link Info",
                    "👁 Who Viewed",
                    "👥 Assigned Users",
                    "🔄 Update Data"
                ])

                # ── Info tab ─────────────────────────────────────────────
                with tab_info:
                    st.markdown("**Full URL:**")
                    st.code(url, language=None)
                    st.markdown(f'<div class="link-box">{url}</div>', unsafe_allow_html=True)
                    st.caption(f"Token: `{row['token']}`")

                    # Quick stats row
                    ms1,ms2,ms3 = st.columns(3)
                    with ms1:
                        st.markdown(f"""<div class='stat-card'>
                            <div class='stat-number' style='color:#00E5FF;font-size:28px;'>{total_assigned}</div>
                            <div class='stat-label'>Assigned</div></div>""", unsafe_allow_html=True)
                    with ms2:
                        st.markdown(f"""<div class='stat-card'>
                            <div class='stat-number' style='color:#4ADE80;font-size:28px;'>{seen_cnt}</div>
                            <div class='stat-label'>Unique Viewers</div></div>""", unsafe_allow_html=True)
                    with ms3:
                        not_seen = len(unseen)
                        clr = '#EF4444' if not_seen > 0 else '#4ADE80'
                        st.markdown(f"""<div class='stat-card'>
                            <div class='stat-number' style='color:{clr};font-size:28px;'>{not_seen}</div>
                            <div class='stat-label'>Not Yet Seen</div></div>""", unsafe_allow_html=True)

                    # Revoke button
                    st.markdown("")
                    if st.button("🗑️ Revoke This Link", key=f"rev_{row['token']}"):
                        deactivate_link(row['token']); st.success("Revoked!"); st.rerun()

                # ── Viewers tab ──────────────────────────────────────────
                with tab_viewers:
                    st.markdown('<div class="section-header">👁 EMPLOYEE VIEW ACTIVITY</div>', unsafe_allow_html=True)

                    if viewers.empty:
                        st.info("Abhi tak kisi ne is link se data nahi dekha.")
                    else:
                        # Seen employees
                        st.markdown("#### ✅ Seen (Viewed Dashboard)")
                        for _, vr in viewers.iterrows():
                            uinfo = None
                            if not users_df.empty:
                                match = users_df[users_df['username']==vr['username']]
                                if len(match):
                                    uinfo = match.iloc[0]
                            nm      = vr['full_name'] or vr['username']
                            uid_str = f"#{int(uinfo['id'])}" if uinfo is not None else ""
                            perms   = json.loads(uinfo['permissions'] or '{}') if uinfo is not None else {}
                            st.markdown(f"""
                            <div class='viewer-card'>
                                <div style='display:flex;justify-content:space-between;align-items:flex-start;'>
                                    <div>
                                        <span class='seen-tag'>✅ SEEN</span>&nbsp;
                                        <span style='color:#00E5FF;font-weight:700;font-size:14px;'>{uid_str} {nm}</span>&nbsp;
                                        <span style='color:#4a6a8a;font-size:12px;font-family:JetBrains Mono,monospace;'>@{vr['username']}</span>
                                    </div>
                                    <div style='text-align:right;'>
                                        <div style='color:#FFD700;font-size:12px;font-family:JetBrains Mono,monospace;'>👁 {int(vr['total_views'])} views</div>
                                    </div>
                                </div>
                                <div style='margin-top:8px;font-size:11px;color:#4a6a8a;font-family:JetBrains Mono,monospace;'>
                                    🕐 First seen: {str(vr['first_seen'])[:16]} &nbsp;|&nbsp;
                                    🕐 Last seen: {str(vr['last_seen'])[:16]}
                                </div>
                                <div style='margin-top:6px;'>{_perm_tags(perms)}</div>
                            </div>""", unsafe_allow_html=True)

                    # Unseen employees
                    if unseen:
                        st.markdown("#### 🔴 Not Yet Viewed")
                        for uname in unseen:
                            uinfo = None
                            if not users_df.empty:
                                match = users_df[users_df['username']==uname]
                                if len(match): uinfo = match.iloc[0]
                            nm      = (uinfo['full_name'] if uinfo is not None and uinfo['full_name'] else uname)
                            uid_str = f"#{int(uinfo['id'])}" if uinfo is not None else ""
                            perms   = json.loads(uinfo['permissions'] or '{}') if uinfo is not None else {}
                            st.markdown(f"""
                            <div class='viewer-card' style='border-color:rgba(239,68,68,0.2);'>
                                <span class='unseen-tag'>❌ NOT SEEN</span>&nbsp;
                                <span style='color:#94A3B8;font-weight:700;font-size:14px;'>{uid_str} {nm}</span>&nbsp;
                                <span style='color:#4a6a8a;font-size:12px;font-family:JetBrains Mono,monospace;'>@{uname}</span>
                                <div style='margin-top:6px;'>{_perm_tags(perms)}</div>
                            </div>""", unsafe_allow_html=True)

                    # Full activity log
                    all_logs = get_view_log(row['token'])
                    if not all_logs.empty:
                        with st.expander("📜 Full Activity Log"):
                            st.dataframe(all_logs.rename(columns={
                                'username':'Username','full_name':'Full Name',
                                'viewed_at':'Viewed At'}), use_container_width=True)

                # ── Assigned Users tab ───────────────────────────────────
                with tab_assigned:
                    st.markdown('<div class="section-header">👥 ASSIGNED EMPLOYEES</div>', unsafe_allow_html=True)

                    if assigned:
                        for uname in assigned:
                            uinfo = None
                            if not users_df.empty:
                                match = users_df[users_df['username']==uname]
                                if len(match): uinfo = match.iloc[0]
                            nm      = (uinfo['full_name'] if uinfo is not None and uinfo['full_name'] else uname)
                            uid_str = f"#{int(uinfo['id'])}" if uinfo is not None else ""
                            perms   = json.loads(uinfo['permissions'] or '{}') if uinfo is not None else {}
                            has_seen = not viewers.empty and uname in viewers['username'].values
                            badge   = '<span class="seen-tag">✅ Seen</span>' if has_seen else '<span class="unseen-tag">❌ Not Seen</span>'
                            st.markdown(f"""
                            <div class='viewer-card'>
                                <div style='display:flex;justify-content:space-between;'>
                                    <span style='color:#00E5FF;font-weight:700;font-size:14px;'>{uid_str} {nm}</span>
                                    {badge}
                                </div>
                                <div style='color:#4a6a8a;font-size:11px;font-family:JetBrains Mono,monospace;margin:4px 0;'>@{uname}</div>
                                <div>{_perm_tags(perms)}</div>
                            </div>""", unsafe_allow_html=True)
                    else:
                        st.info("No users specifically assigned.")

                    st.markdown("---")
                    st.markdown("**➕ Edit Assignment:**")
                    if not users_df.empty:
                        act_u = users_df[users_df['is_active']==1]['username'].tolist()
                        new_a = st.multiselect("Assign Users", act_u, default=assigned,
                                               key=f"ma_{row['token']}")
                        if st.button("💾 Save Assignment", key=f"sa_{row['token']}"):
                            update_link_assigned_users(row['token'], new_a)
                            st.success("✅ Saved!"); st.rerun()

                # ── Update Data tab ──────────────────────────────────────
                with tab_data:
                    st.markdown('<div class="section-header">🔄 UPDATE LINK DATA</div>', unsafe_allow_html=True)
                    upf = st.file_uploader("New Excel file", type=["xlsx","xls"], key=f"up_{row['token']}")
                    if upf and st.button("🔄 Update", key=f"ub_{row['token']}"):
                        df = process_excel(upf)
                        save_data_for_token(row['token'], df, upf.name)
                        st.success(f"✅ Data updated — {len(df)} rows")

    # ── 4. View Dashboard ──────────────────────────────────────────────────
    elif page == "📊 View Dashboard":
        lks = get_share_links()
        if lks.empty: st.info("No links yet."); return
        sel = st.selectbox("Select Dashboard", lks['token'].tolist(),
                           format_func=lambda t: lks[lks['token']==t]['label'].values[0]+f" ({t[:8]}...)")
        df, fn = load_data_for_token(sel)
        if df is None: st.warning("No data uploaded for this link."); return
        st.markdown(f"**Viewing:** `{fn}` — {len(df)} records (Master View)")
        show_dashboard(df, {})

# ─────────────────────────────────────────────────────────────────────────────
#  EMPLOYEE DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
def show_employee_dashboard():
    token    = st.session_state.access_token
    uinfo    = get_user_info(st.session_state.username)
    perms    = uinfo.get("permissions",{}) if uinfo else {}
    full_nm  = uinfo.get("full_name","") if uinfo else ""
    disp_nm  = full_nm or st.session_state.username

    # ── Log view on first render ──────────────────────────────────────────
    log_key = f"logged_{token}_{st.session_state.username}"
    if log_key not in st.session_state:
        log_view(token, st.session_state.username, full_nm,
                 st.session_state.get('session_id',''))
        st.session_state[log_key] = True

    with st.sidebar:
        st.markdown('<div class="user-badge">👤 EMPLOYEE</div>', unsafe_allow_html=True)
        st.markdown(f"**{disp_nm}**")
        if full_nm: st.caption(f"@{st.session_state.username}")
        st.markdown("---")
        st.markdown("**My Data Access:**")
        st.markdown(_perm_tags(perms), unsafe_allow_html=True)
        st.markdown("---")
        if st.button("🚪 Logout"):
            delete_persistent_session(st.query_params.get('sid',''))
            # Keep ?token= so user can log back in via same link, clear only sid
            _qp = dict(st.query_params)
            _qp.pop('sid', None)
            st.query_params.clear()
            st.query_params.update(_qp)
            for k in ['role','username','access_token','_session_restored']: st.session_state[k]=None
            st.rerun()

    df, fn = load_data_for_token(token)
    if df is None:
        st.warning("⚠️ No data available. Contact administrator."); return

    fdf = apply_permissions(df, perms)
    if fdf.empty:
        st.warning("⚠️ No data within your permissions."); return

    acc_lbl = "Full Access" if not perms else "Restricted Access"
    st.markdown(f"<p style='color:#4a6a8a;font-size:12px;font-family:JetBrains Mono,monospace;'>"
                f"DATA: {fn} &nbsp;|&nbsp; {len(fdf)} records &nbsp;|&nbsp; {acc_lbl}</p>",
                unsafe_allow_html=True)
    show_dashboard(fdf, perms)

# ─────────────────────────────────────────────────────────────────────────────
#  CORE DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
def show_dashboard(df, permissions):
    st.markdown("""
    <div style='padding:4px 0 16px;'>
        <div class='glow-title'>ISSUES INTELLIGENCE DASHBOARD</div>
        <div class='sub-title'>Real-time Analytics & Insights Platform</div>
    </div>""", unsafe_allow_html=True)

    req = ['Ser. No','Country','Continent','Current Milestone','Department','HP category',
           'Issue diss. Date','Aging']
    miss = [c for c in req if c not in df.columns]
    if miss: st.error(f"Missing columns: {', '.join(miss)}"); return

    # Sidebar filters
    st.sidebar.markdown('<div class="section-header">🔽 FILTERS</div>', unsafe_allow_html=True)
    conts     = sorted(df['Continent'].dropna().unique().tolist())
    sel_cont  = st.sidebar.selectbox("Continent", ["All"]+conts)
    pool      = df if sel_cont=="All" else df[df['Continent']==sel_cont]
    sel_ctry  = st.sidebar.selectbox("Country", ["All"]+sorted(pool['Country'].dropna().unique().tolist()))
    depts     = sorted(df['Department'].dropna().unique().tolist())
    sel_dept  = st.sidebar.multiselect("Department", depts, default=depts)
    hps       = sorted(df['HP category'].dropna().unique().tolist())
    sel_hp    = st.sidebar.multiselect("HP Category", hps, default=hps)
    miles     = sorted(df['Current Milestone'].replace('',pd.NA).dropna().unique().tolist())
    sel_mile  = st.sidebar.multiselect("Milestone", miles, default=miles)

    df = _reparse_dt(df)
    vd = df['Issue diss. Date'].dropna()
    if len(vd):
        mn,mx      = vd.min().date(), vd.max().date()
        date_range = st.sidebar.date_input("Date Range", value=(mn,mx), min_value=mn, max_value=mx)
    else:
        date_range = None
    n_bins = st.sidebar.slider("Aging Bins", 5, 60, 20)

    fdf = df.copy()
    if sel_cont!="All":   fdf = fdf[fdf['Continent']==sel_cont]
    if sel_ctry!="All":   fdf = fdf[fdf['Country']==sel_ctry]
    if sel_dept:          fdf = fdf[fdf['Department'].isin(sel_dept)]
    if sel_hp:            fdf = fdf[fdf['HP category'].isin(sel_hp)]
    if sel_mile:          fdf = fdf[fdf['Current Milestone'].isin(sel_mile)]
    if date_range and len(date_range)==2:
        fdf = fdf[(fdf['Issue diss. Date']>=pd.Timestamp(date_range[0])) &
                  (fdf['Issue diss. Date']<=pd.Timestamp(date_range[1]))]
    if fdf.empty: st.warning("No data for selected filters."); return

    col_set = CONT_COLORS.get(sel_cont if sel_cont!="All" else "Unknown", CONT_COLORS['Unknown'])

    # KPIs
    st.markdown('<div class="section-header">⚡ KEY METRICS</div>', unsafe_allow_html=True)
    total    = int(fdf['Ser. No'].nunique())
    pdi      = int((fdf['Issue Type']=='PDI').sum()) if 'Issue Type' in fdf.columns else 0
    svc      = int((fdf['Issue Type']=='Service').sum()) if 'Issue Type' in fdf.columns else 0
    avg_age  = round(fdf['Aging'].dropna().mean(),1) if fdf['Aging'].notna().any() else 0
    impl     = int((fdf['Current Milestone']=='Implemented').sum())
    ctries   = int(fdf['Country'].nunique())
    open_iss = total-impl

    kpis = [("📋 Total",total,"#00E5FF"),("🔧 PDI",pdi,"#FFD700"),("⚙️ Service",svc,"#FF6B35"),
            ("⏳ Avg Aging",f"{avg_age}d","#F472B6"),("✅ Implemented",impl,"#4ADE80"),
            ("🔴 Open",open_iss,"#EF4444"),("🌍 Countries",ctries,"#A78BFA")]
    cols = st.columns(7)
    for i,(lbl,val,clr) in enumerate(kpis):
        with cols[i]:
            st.markdown(f"""<div class="stat-card">
                <div class="stat-number" style="color:{clr};">{val}</div>
                <div class="stat-label">{lbl}</div></div>""", unsafe_allow_html=True)
    st.markdown("---")

    t1,t2,t3,t4 = st.tabs(["📅 Timeline & Distribution","🌍 World Map",
                             "🎯 Milestone & Analysis","🔮 3D Analytics"])

    # ── Tab 1 ──────────────────────────────────────────────────────────────
    with t1:
        td = (fdf.dropna(subset=['Issue diss. Date'])
                .set_index('Issue diss. Date').resample('W')['Ser. No']
                .count().reset_index().rename(columns={'Issue diss. Date':'Week','Ser. No':'Issues'}))
        fl = px.line(td, x='Week', y='Issues', color_discrete_sequence=[col_set[2]],
                     template='plotly_dark', markers=True)
        fl.update_traces(line_width=2.5)
        fl.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(6,13,26,0.5)',
                         title="Weekly Issue Count")
        st.plotly_chart(fl, use_container_width=True, key="pchart_1")

        fh = go.Figure(data=[go.Histogram(x=fdf['Aging'].dropna(), nbinsx=n_bins,
                                           marker_color=col_set[1],
                                           marker_line_color='rgba(0,229,255,0.3)',
                                           marker_line_width=1)])
        fh.update_layout(xaxis_title='Aging (Days)', yaxis_title='Count',
                         template='plotly_dark', height=380, title="Aging Distribution",
                         paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(6,13,26,0.5)')
        st.plotly_chart(fh, use_container_width=True, key="pchart_2")

        vc1,vc2 = st.columns(2)
        with vc1:
            fv = px.violin(fdf.dropna(subset=['Aging']), y='Aging', box=True, points="all",
                           color_discrete_sequence=[col_set[0]], template='plotly_dark',
                           title="Aging Violin")
            fv.update_layout(xaxis={'visible':False}, paper_bgcolor='rgba(0,0,0,0)',
                              plot_bgcolor='rgba(6,13,26,0.5)')
            st.plotly_chart(fv, use_container_width=True, key="pchart_3")
        with vc2:
            da = fdf.dropna(subset=['Aging','Department'])
            fb = px.box(da, x='Department', y='Aging', color='Department',
                        color_discrete_map={d:DEPT_COL.get(d,'#999') for d in da['Department'].unique()},
                        template='plotly_dark', title="Aging by Department")
            fb.update_layout(showlegend=False, xaxis_tickangle=-30,
                              paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(6,13,26,0.5)')
            st.plotly_chart(fb, use_container_width=True, key="pchart_4")

        if 'Issue Type' in fdf.columns:
            tg = fdf.groupby('Issue Type')['Ser. No'].count().reset_index().rename(columns={'Ser. No':'Count'})
            fb2 = px.bar(tg, x='Issue Type', y='Count', color='Issue Type',
                         template='plotly_dark', text='Count', title="PDI vs Service")
            fb2.update_traces(textposition='outside')
            fb2.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(6,13,26,0.5)')
            st.plotly_chart(fb2, use_container_width=True, key="pchart_5")

    # ── Tab 2 ──────────────────────────────────────────────────────────────
    with t2:
        md = (fdf.groupby(['Country','Continent','ISO3'])
                .agg(Issues=('Ser. No','count'), Avg_Aging=('Aging','mean'))
                .reset_index().dropna(subset=['ISO3']))
        md['Avg_Aging'] = md['Avg_Aging'].round(1)

        fm1 = px.choropleth(md, locations='ISO3', color='Issues', hover_name='Country',
                             color_continuous_scale='YlOrRd', projection='natural earth',
                             template='plotly_dark', title="Issue Count by Country")
        fm1.update_geos(showcoastlines=True,coastlinecolor='#1E3A5F',showland=True,landcolor='#0a1628',
                        showocean=True,oceancolor='#030712',showcountries=True,countrycolor='#1E3A5F')
        fm1.update_layout(height=500,margin=dict(l=0,r=0,t=30,b=0),
                          geo=dict(bgcolor='#030712'),paper_bgcolor='#030712',font=dict(color='white'))
        st.plotly_chart(fm1, use_container_width=True, key="pchart_6")

        fm2 = px.choropleth(md, locations='ISO3', color='Avg_Aging', hover_name='Country',
                             color_continuous_scale='RdYlGn_r', projection='natural earth',
                             template='plotly_dark', title="Average Aging by Country")
        fm2.update_geos(showcoastlines=True,coastlinecolor='#1E3A5F',showland=True,landcolor='#0a1628',
                        showocean=True,oceancolor='#030712',showcountries=True,countrycolor='#1E3A5F')
        fm2.update_layout(height=500,margin=dict(l=0,r=0,t=30,b=0),
                          geo=dict(bgcolor='#030712'),paper_bgcolor='#030712',font=dict(color='white'))
        st.plotly_chart(fm2, use_container_width=True, key="pchart_7")

        gc1,gc2 = st.columns(2)
        with gc1:
            cc = (fdf.groupby('Country')['Ser. No'].count().reset_index()
                    .rename(columns={'Ser. No':'Count'}).sort_values('Count',ascending=True).tail(20))
            fcc = px.bar(cc, y='Country', x='Count', orientation='h', color='Count',
                         color_continuous_scale='Blues', template='plotly_dark', text='Count',
                         title="Top Countries")
            fcc.update_layout(coloraxis_showscale=False, height=max(380,len(cc)*22),
                               paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(6,13,26,0.5)')
            fcc.update_traces(textposition='outside')
            st.plotly_chart(fcc, use_container_width=True, key="pchart_8")
        with gc2:
            cc2  = fdf.groupby('Continent')['Ser. No'].count().reset_index().rename(columns={'Ser. No':'Count'})
            cmap = {c:CONT_COLORS.get(c,CONT_COLORS['Unknown'])[0] for c in cc2['Continent']}
            fd   = px.pie(cc2, values='Count', names='Continent', hole=0.55,
                          color='Continent', color_discrete_map=cmap,
                          template='plotly_dark', title="By Continent")
            fd.update_traces(textposition='outside', textinfo='label+percent+value')
            fd.update_layout(paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fd, use_container_width=True, key="pchart_9")

    # ── Tab 3 ──────────────────────────────────────────────────────────────
    with t3:
        mc = (fdf[fdf['Current Milestone']!=''].groupby('Current Milestone')['Ser. No']
              .count().reset_index().rename(columns={'Ser. No':'Count'}).sort_values('Count',ascending=False))
        fmp = px.pie(mc, values='Count', names='Current Milestone', hole=0.5,
                     color='Current Milestone',
                     color_discrete_map={m:MILE_COL.get(m,'#94A3B8') for m in mc['Current Milestone']},
                     template='plotly_dark', title="Milestone Breakdown")
        fmp.update_traces(textposition='outside', textinfo='percent+label')
        fmp.update_layout(paper_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fmp, use_container_width=True, key="pchart_10")

        hc = (fdf.groupby('HP category')['Ser. No'].count().reset_index()
                .rename(columns={'Ser. No':'Count'}).sort_values('Count',ascending=False))
        fhp = px.bar(hc, x='HP category', y='Count', color='Count',
                     color_continuous_scale='Cividis', text='Count',
                     template='plotly_dark', title="Issues by HP Category")
        fhp.update_traces(textposition='outside')
        fhp.update_layout(coloraxis_showscale=False, xaxis_tickangle=-20,
                           paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(6,13,26,0.5)')
        st.plotly_chart(fhp, use_container_width=True, key="pchart_11")

        pm = fdf['Closure Month - Plan'].pipe(lambda s: pd.to_datetime(s,errors='coerce')).dt.to_period('M').value_counts().sort_index()
        am = fdf['Closure Month'].dt.to_period('M').value_counts().sort_index()
        ap = sorted(set(pm.index.tolist()+am.index.tolist()))
        if ap:
            pad = pd.DataFrame({'Month':[str(p) for p in ap],
                                 'Plan':[pm.get(p,0) for p in ap],
                                 'Actual':[am.get(p,0) for p in ap]})
            fpa = go.Figure()
            fpa.add_trace(go.Bar(x=pad['Month'],y=pad['Plan'],name='Plan',
                                  marker_color='#22D3EE',text=pad['Plan'],textposition='outside'))
            fpa.add_trace(go.Bar(x=pad['Month'],y=pad['Actual'],name='Actual',
                                  marker_color='#4ADE80',text=pad['Actual'],textposition='outside'))
            fpa.update_layout(barmode='group',template='plotly_dark',height=380,
                               title="Plan vs Actual Closure",
                               paper_bgcolor='rgba(0,0,0,0)',plot_bgcolor='rgba(6,13,26,0.5)')
            st.plotly_chart(fpa, use_container_width=True, key="pchart_12")

    # ── Tab 4 ──────────────────────────────────────────────────────────────
    with t4:
        st.markdown("""<div style='background:linear-gradient(90deg,rgba(0,229,255,0.06),transparent);
            border:1px solid rgba(0,229,255,0.15);border-radius:12px;padding:16px;margin-bottom:20px;'>
            <span style='color:#00E5FF;font-family:Orbitron,sans-serif;font-size:13px;'>🔮 3D INTERACTIVE</span><br>
            <span style='color:#4a6a8a;font-size:12px;'>Rotate • Zoom • Hover</span></div>""",
            unsafe_allow_html=True)

        st.markdown('<div class="section-header">🔵 3D SCATTER — AGING × MONTH × FAILURES</div>', unsafe_allow_html=True)
        f = make_3d_scatter(fdf)
        if f:
            st.plotly_chart(f, use_container_width=True, key="pchart_13")
        else:
            st.info("Not enough data for 3D Scatter.")

        st.markdown('<div class="section-header">🌊 3D SURFACE — CONTINENT × MILESTONE × ISSUES</div>', unsafe_allow_html=True)
        f = make_3d_surface(fdf)
        if f:
            st.plotly_chart(f, use_container_width=True, key="pchart_14")
        else:
            st.info("Not enough data for 3D Surface.")

        st.markdown('<div class="section-header">📡 3D RIBBON — WEEKLY ISSUES BY CONTINENT</div>', unsafe_allow_html=True)
        f = make_3d_ribbon(fdf)
        if f:
            st.plotly_chart(f, use_container_width=True, key="pchart_15")
        else:
            st.info("Not enough data for 3D Ribbon.")

        st.markdown('<div class="section-header">⚡ 3D BUBBLE — DEPT × HP CATEGORY × AVG AGING</div>', unsafe_allow_html=True)
        f = make_3d_bubble(fdf)
        if f:
            st.plotly_chart(f, use_container_width=True, key="pchart_16")
        else:
            st.info("Not enough data for 3D Bubble.")

        st.markdown('<div class="section-header">🎇 SUNBURST — CONTINENT → COUNTRY</div>', unsafe_allow_html=True)
        sd = fdf.groupby(['Continent','Country'])['Ser. No'].count().reset_index().rename(columns={'Ser. No':'Count'})
        sd = sd[sd['Count']>0]
        if not sd.empty:
            fs = px.sunburst(sd, path=['Continent','Country'], values='Count',
                             color='Count', color_continuous_scale='Blues', template='plotly_dark')
            fs.update_layout(height=540, paper_bgcolor='rgba(0,0,0,0)',
                              font=dict(family='Space Grotesk'))
            st.plotly_chart(fs, use_container_width=True, key="pchart_17")

        st.markdown('<div class="section-header">📐 PARALLEL COORDINATES</div>', unsafe_allow_html=True)
        pc = fdf.copy()
        pc['Month_num'] = pc['Issue diss. Date'].dt.month.fillna(0)
        pc['Type_num']  = (pc['Issue Type']=='PDI').astype(int) if 'Issue Type' in pc.columns else 0
        ce              = {c:i for i,c in enumerate(sorted(pc['Continent'].dropna().unique()))}
        pc['Cont_num']  = pc['Continent'].map(ce).fillna(-1)
        pcn = pc[['Aging','Month_num','Type_num','Cont_num']].dropna()
        if len(pcn)>5:
            fpc = go.Figure(data=[go.Parcoords(
                line=dict(color=pcn['Aging'], colorscale='Plasma', showscale=True,
                          colorbar=dict(title='Aging', thickness=12)),
                dimensions=[
                    dict(range=[pcn['Aging'].min(),pcn['Aging'].max()], label='Aging', values=pcn['Aging']),
                    dict(range=[1,12], label='Month', values=pcn['Month_num']),
                    dict(range=[0,1], tickvals=[0,1], ticktext=['Service','PDI'], label='Type', values=pcn['Type_num']),
                    dict(range=[0,max(ce.values()) if ce else 1],
                         tickvals=list(ce.values()), ticktext=list(ce.keys()),
                         label='Continent', values=pcn['Cont_num']),
                ]
            )])
            fpc.update_layout(template='plotly_dark', height=400,
                               paper_bgcolor='rgba(0,0,0,0)',
                               font=dict(family='Space Grotesk', color='#94a3b8'))
            st.plotly_chart(fpc, use_container_width=True, key="pchart_18")

    with st.expander(f"📋 Raw Data — {len(fdf)} records"):
        st.dataframe(fdf, use_container_width=True)
        st.download_button("⬇️ CSV Download", fdf.to_csv(index=False).encode('utf-8'),
                           file_name="issues_data.csv", mime='text/csv')

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ROUTER
# ─────────────────────────────────────────────────────────────────────────────
def main():
    if url_token:
        if st.session_state.role == 'user':
            show_employee_dashboard()
        elif st.session_state.role == 'master':
            st.session_state.access_token = url_token
            show_employee_dashboard()
        else:
            show_employee_login(url_token)
        return
    if st.session_state.role == 'master':
        show_master_dashboard()
        return
    show_master_login()

if __name__ == "__main__":
    main()
