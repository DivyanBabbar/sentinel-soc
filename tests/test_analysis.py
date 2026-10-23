from datetime import UTC, datetime

from sentinel import analysis
from sentinel.analysis import score_event
from sentinel.models import SecurityEvent


def test_malware_is_high_risk():
    event = SecurityEvent(
        timestamp=datetime.now(UTC), event_type="malware_detected", actor="service-account", severity="critical"
    )
    score, findings = score_event(event)
    assert score >= 88 and "Malware indicator reported" in findings


def test_failed_api_call_adds_probe_signal():
    event = SecurityEvent(timestamp=datetime.now(UTC), event_type="api_call", actor="user", outcome="failure")
    score, findings = score_event(event)
    assert score == 15 and "Failed API call may indicate probing" in findings


def test_missing_source_ips_do_not_create_password_spray_finding(monkeypatch):
    now = datetime.now(UTC)
    events = [SecurityEvent(timestamp=now, event_type="login_failed", actor="user") for _ in range(5)]
    monkeypatch.setattr(analysis, "recent_events", lambda _limit: events)

    incident = analysis.correlate(events[0])

    assert incident.risk_score == 60
    assert not any("Password-spray pattern" in finding for finding in incident.findings)
