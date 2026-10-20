from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from sentinel.analysis import analyze_recent, report_markdown
from sentinel.models import Incident, SecurityEvent
from sentinel.storage import (
    claim_containment,
    get_incident,
    initialize,
    list_incidents,
    recent_events,
    save_events,
    save_incident,
)
app=FastAPI(title="Sentinel SOC",version="1.0.0",description="Threat triage and analyst-approved simulated containment.")
app.mount("/static",StaticFiles(directory=Path(__file__).parent/"static"),name="static")
@app.on_event("startup")
def startup():initialize()
@app.get("/",include_in_schema=False)
def home():return FileResponse(Path(__file__).parent/"static"/"index.html")
@app.get("/health")
def health():return {"status":"ok","service":"sentinel-soc"}
@app.get("/v1/events")
def events():return recent_events(100)
@app.post("/v1/events",status_code=202)
def ingest(event:SecurityEvent):return {"accepted":save_events([event]),"event_id":str(uuid4())}
@app.post("/v1/events/batch",status_code=202)
def ingest_batch(events:list[SecurityEvent]):
    if not 1<=len(events)<=1000:raise HTTPException(422,"Batch size must be between 1 and 1000.")
    return {"accepted":save_events(events)}
@app.post("/v1/incidents/analyze")
def analyze():return analyze_recent()
@app.get("/v1/incidents")
def incidents():return list_incidents()
@app.get("/v1/incidents/{iid}/report",response_class=PlainTextResponse)
def report(iid:str):
    row=get_incident(iid)
    if not row:raise HTTPException(404,"Incident not found")
    return report_markdown(Incident.model_validate(row))
@app.post("/v1/incidents/{iid}/contain/approve")
def approve(iid:str):
    row=get_incident(iid)
    if not row:raise HTTPException(404,"Incident not found")
    if row["recommended_action"]=="review":raise HTTPException(409,"No containment action is recommended")
    if row["containment_status"]!="not_approved":raise HTTPException(409,"Incident is not awaiting approval")
    row["containment_status"]="approved";save_incident(Incident.model_validate(row));return row
@app.post("/v1/incidents/{iid}/contain/execute")
def execute(iid:str):
    row=get_incident(iid)
    if not row:raise HTTPException(404,"Incident not found")
    if row["containment_status"]!="approved":raise HTTPException(409,"Analyst approval is required")
    key=f"{iid}:{row['recommended_action']}"
    if not claim_containment(key,iid,row["recommended_action"]):raise HTTPException(409,"Containment action already recorded")
    row["containment_status"]="simulated";row["status"]="contained";save_incident(Incident.model_validate(row))
    return {"incident":row,"execution":"simulated","message":"No account or network control was changed."}
@app.post("/v1/demo/load")
def demo():
    t=datetime.now(UTC);ip="198.51.100.42";actor="alex.chen@example.test"
    events=[
      SecurityEvent(timestamp=t-timedelta(minutes=8),event_type="login_failed",actor=actor,source_ip=ip,outcome="failure",severity="medium",action="password login",details="Synthetic failed login 1"),
      *[SecurityEvent(timestamp=t-timedelta(minutes=i),event_type="login_failed",actor=actor,source_ip=ip,outcome="failure",severity="medium",action="password login",details=f"Synthetic failed login {i}") for i in range(7,2,-1)],
      SecurityEvent(timestamp=t-timedelta(minutes=1),event_type="privilege_change",actor=actor,source_ip=ip,outcome="success",severity="high",action="role elevated",resource="billing-admin",details="Synthetic privilege grant after spray"),
      SecurityEvent(timestamp=t,event_type="api_call",actor=actor,source_ip=ip,outcome="failure",severity="high",action="list customer exports",resource="/v1/exports",details="Synthetic API misuse")]
    save_events(events);return {"accepted":len(events),"message":"Synthetic password-spray and privilege-escalation scenario loaded."}
