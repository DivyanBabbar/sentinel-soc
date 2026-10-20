import json
import sqlite3
from pathlib import Path
from sentinel.config import settings

def connect():
    root=Path(settings.data_dir); root.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(root/"sentinel.db",timeout=10); db.row_factory=sqlite3.Row; return db

def initialize():
    with connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, timestamp TEXT, event_type TEXT, actor TEXT, source_ip TEXT, resource TEXT, action TEXT, outcome TEXT, severity TEXT, details TEXT)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_actor_time ON events(actor,timestamp)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(source_ip,timestamp)")
        db.execute("CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, actor TEXT, risk_score INTEGER, status TEXT, payload TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS containment(idempotency_key TEXT PRIMARY KEY, incident_id TEXT, action TEXT)")

def save_events(events):
    with connect() as db:
        cur=db.executemany("INSERT INTO events(timestamp,event_type,actor,source_ip,resource,action,outcome,severity,details) VALUES(?,?,?,?,?,?,?,?,?)",[(e.timestamp.isoformat(),e.event_type,e.actor,e.source_ip,e.resource,e.action,e.outcome,e.severity,e.details) for e in events]);return cur.rowcount

def recent_events(limit=300):
    with connect() as db: rows=db.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",(limit,)).fetchall()
    from sentinel.models import SecurityEvent
    return [SecurityEvent(timestamp=r["timestamp"],event_type=r["event_type"],actor=r["actor"],source_ip=r["source_ip"],resource=r["resource"],action=r["action"],outcome=r["outcome"],severity=r["severity"],details=r["details"]) for r in rows]

def save_incident(incident):
    with connect() as db: db.execute("INSERT OR REPLACE INTO incidents VALUES(?,?,?, ?,?)",(incident.incident_id,incident.actor,incident.risk_score,incident.status,incident.model_dump_json()))

def get_incident(iid):
    with connect() as db: row=db.execute("SELECT payload FROM incidents WHERE id=?",(iid,)).fetchone()
    return json.loads(row[0]) if row else None

def list_incidents():
    with connect() as db: rows=db.execute("SELECT payload FROM incidents ORDER BY risk_score DESC LIMIT 100").fetchall()
    return [json.loads(r[0]) for r in rows]

def claim_containment(key,iid,action):
    with connect() as db:
        try: db.execute("INSERT INTO containment VALUES(?,?,?)",(key,iid,action));return True
        except sqlite3.IntegrityError:return False
