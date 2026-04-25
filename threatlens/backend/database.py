"""
database.py — SQLite persistence for ThreatLens AI.
"""
import sqlite3, os, json, uuid
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "threatlens.db")

def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id           TEXT PRIMARY KEY,
            input_type   TEXT NOT NULL,
            input_value  TEXT NOT NULL,
            verdict      TEXT NOT NULL,
            overall_risk INTEGER NOT NULL,
            threat_level TEXT,
            confidence   INTEGER,
            campaign_id  TEXT,
            campaign_name TEXT,
            explanation  TEXT,
            report_card  TEXT,
            features     TEXT,
            shap_values  TEXT,
            created_at   TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()
    print("[ThreatLens] Database ready:", DB_PATH)

def save_scan(scan_id, input_type, input_value, verdict, overall_risk,
              threat_level, confidence, campaign_id, campaign_name,
              explanation, report_card, features, shap_values=None):
    try:
        conn = get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO scans
            (id,input_type,input_value,verdict,overall_risk,threat_level,
             confidence,campaign_id,campaign_name,explanation,report_card,
             features,shap_values,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_id, input_type, str(input_value)[:200], verdict, overall_risk,
            threat_level, confidence, campaign_id, campaign_name,
            explanation,
            json.dumps(report_card) if report_card else "{}",
            json.dumps(features)    if features    else "{}",
            json.dumps(shap_values) if shap_values else None,
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] save_scan error: {e}")

def get_history(limit=20):
    try:
        conn = get_conn()
        rows = conn.execute("""
            SELECT id, input_type, input_value, verdict, overall_risk,
                   threat_level, campaign_name, created_at
            FROM scans ORDER BY created_at DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] get_history error: {e}")
        return []

def get_stats():
    try:
        conn = get_conn()
        total    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        phishing = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict='PHISHING'").fetchone()[0]
        camps    = conn.execute("SELECT COUNT(DISTINCT campaign_id) FROM scans WHERE campaign_id IS NOT NULL").fetchone()[0]
        conn.close()
        return {
            "total_scanned":  total,
            "phishing_found": phishing,
            "safe_found":     total - phishing,
            "blocked":        phishing,
            "campaigns_seen": camps,
        }
    except Exception as e:
        print(f"[DB] get_stats error: {e}")
        return {"total_scanned":0,"phishing_found":0,"safe_found":0,"blocked":0,"campaigns_seen":0}

def get_scan_by_id(scan_id):
    try:
        conn = get_conn()
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["report_card"] = json.loads(d["report_card"]) if d["report_card"] else {}
        d["features"]    = json.loads(d["features"])    if d["features"]    else {}
        d["shap_values"] = json.loads(d["shap_values"]) if d["shap_values"] else None
        return d
    except Exception as e:
        print(f"[DB] get_scan_by_id error: {e}")
        return None

def get_history_for_export(limit=500):
    try:
        conn = get_conn()
        rows = conn.execute("""
            SELECT id, input_type, input_value, verdict, overall_risk,
                   threat_level, confidence, campaign_name, created_at
            FROM scans ORDER BY created_at DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] get_history_for_export error: {e}")
        return []

def init_bulk_table():
    """Create bulk_scans table if not exists."""
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bulk_scans (
            id           TEXT PRIMARY KEY,
            filename     TEXT,
            total        INTEGER,
            phishing     INTEGER,
            safe         INTEGER,
            results_json TEXT,
            created_at   TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

def save_bulk_scan(bulk_id, filename, total, phishing, safe, results):
    try:
        conn = get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO bulk_scans
            (id, filename, total, phishing, safe, results_json, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (bulk_id, filename, total, phishing, safe,
              json.dumps(results), datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] save_bulk_scan error: {e}")

def get_bulk_history(limit=20):
    try:
        conn = get_conn()
        rows = conn.execute("""
            SELECT id, filename, total, phishing, safe, created_at
            FROM bulk_scans ORDER BY created_at DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] get_bulk_history error: {e}")
        return []

def get_bulk_scan_by_id(bulk_id):
    try:
        conn = get_conn()
        row = conn.execute("SELECT * FROM bulk_scans WHERE id=?", (bulk_id,)).fetchone()
        conn.close()
        if not row: return None
        d = dict(row)
        d["results"] = json.loads(d["results_json"]) if d["results_json"] else []
        return d
    except Exception as e:
        print(f"[DB] get_bulk_scan_by_id error: {e}")
        return None
