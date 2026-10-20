from datetime import UTC,datetime

from sentinel.analysis import score_event
from sentinel.models import SecurityEvent

def test_malware_is_high_risk():
    event=SecurityEvent(timestamp=datetime.now(UTC),event_type="malware_detected",actor="service-account",severity="critical")
    score,findings=score_event(event)
    assert score>=88 and "Malware indicator reported" in findings

def test_failed_api_call_adds_probe_signal():
    event=SecurityEvent(timestamp=datetime.now(UTC),event_type="api_call",actor="user",outcome="failure")
    score,findings=score_event(event)
    assert score==15 and "Failed API call may indicate probing" in findings
