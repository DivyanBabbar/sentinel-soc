from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sentinel.models import Incident, SecurityEvent
from sentinel.storage import recent_events, save_incident

BASE={"login_failed":12,"login_success":2,"privilege_change":28,"api_call":3,"malware_detected":60,"cloud_policy_change":22,"data_access":14}
SEVERITY={"low":0,"medium":8,"high":18,"critical":28}

def score_event(event:SecurityEvent)->tuple[int,list[str]]:
    score=BASE[event.event_type]+SEVERITY[event.severity];findings=[]
    if event.event_type=="login_failed": findings.append("Failed authentication attempt")
    if event.event_type=="privilege_change": findings.append("Privilege or role change requires review")
    if event.event_type=="malware_detected": findings.append("Malware indicator reported")
    if event.event_type=="api_call" and event.outcome=="failure": score+=12;findings.append("Failed API call may indicate probing")
    if event.event_type=="cloud_policy_change": findings.append("Cloud security policy changed")
    if event.event_type=="data_access" and event.severity in {"high","critical"}: score+=10;findings.append("Sensitive data access at elevated severity")
    return min(100,score),findings

def correlate(seed:SecurityEvent,window_minutes:int=15)->Incident:
    cutoff=seed.timestamp-timedelta(minutes=window_minutes);ceiling=seed.timestamp+timedelta(minutes=window_minutes)
    events=[e for e in recent_events(1000) if cutoff<=e.timestamp<=ceiling and (e.actor==seed.actor or (seed.source_ip and e.source_ip==seed.source_ip))]
    if seed not in events: events.append(seed)
    events.sort(key=lambda e:e.timestamp)
    failed=[e for e in events if e.event_type=="login_failed"]
    max_fails=max((sum(x.source_ip==ip for x in failed) for ip in {x.source_ip for x in failed}),default=0)
    points=sum(score_event(e)[0] for e in events)
    findings=[]
    for e in events: findings.extend(score_event(e)[1])
    if max_fails>=5: points+=25;findings.append(f"Password-spray pattern: {max_fails} failed logins observed")
    if len({e.event_type for e in events})>=3: points+=12;findings.append("Multiple distinct security event types correlate in one time window")
    score=min(100,points)
    severity="critical" if score>=85 else "high" if score>=60 else "medium" if score>=30 else "low"
    action="disable_account" if any(e.event_type=="malware_detected" for e in events) or score>=85 else "block_ip" if seed.source_ip and score>=60 else "review"
    summary=f"{len(events)} correlated events for {seed.actor}; risk score {score}/100 ({severity})."
    return Incident(incident_id=str(uuid4()),actor=seed.actor,risk_score=score,severity=severity,summary=summary,findings=list(dict.fromkeys(findings)),events=events,recommended_action=action)

def analyze_recent()->list[Incident]:
    events=recent_events(300); groups={}
    for event in events:
        key=(event.actor,event.source_ip)
        if key not in groups: groups[key]=correlate(event)
    incidents=list(groups.values())
    for incident in incidents: save_incident(incident)
    return incidents

def report_markdown(incident:Incident)->str:
    findings="\n".join(f"- {x}" for x in incident.findings) or "- No strong rule findings; review source events."
    timeline="\n".join(f"- {e.timestamp.isoformat()} · {e.event_type} · {e.actor} · {e.action or e.resource} · {e.outcome}" for e in incident.events)
    return f"# Security incident {incident.incident_id}\n\n**Severity:** {incident.severity.upper()}  \n**Risk:** {incident.risk_score}/100  \n**Actor:** {incident.actor}  \n**Status:** {incident.status}\n\n## Summary\n\n{incident.summary}\n\n## Findings\n\n{findings}\n\n## Timeline\n\n{timeline}\n\n## Recommended next step\n\n`{incident.recommended_action}` (requires analyst approval; current implementation is simulation-only).\n\n## Analyst note\n\nScores prioritize investigation and are not proof of malicious activity. Validate identity, asset criticality, and source system context before response.\n"
