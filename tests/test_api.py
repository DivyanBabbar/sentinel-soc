import pytest
from fastapi.testclient import TestClient
from sentinel import storage
from sentinel.api import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(storage.settings, "data_dir", str(tmp_path))
    with TestClient(app) as c:
        yield c


def test_demo_correlates_password_spray_and_gates_containment(client):
    demo = client.post("/v1/demo/load")
    assert demo.status_code == 200 and demo.json()["accepted"] == 8
    incidents = client.post("/v1/incidents/analyze").json()
    incident = incidents[0]
    iid = incident["incident_id"]
    assert incident["risk_score"] == 100 and incident["recommended_action"] == "disable_account"
    assert any("Password-spray" in f for f in incident["findings"])
    assert client.post(f"/v1/incidents/{iid}/contain/execute").status_code == 409
    assert client.post(f"/v1/incidents/{iid}/contain/approve").status_code == 200
    result = client.post(f"/v1/incidents/{iid}/contain/execute")
    assert result.status_code == 200 and result.json()["execution"] == "simulated"
    assert client.post(f"/v1/incidents/{iid}/contain/execute").status_code == 409


def test_report_contains_evidence_and_analyst_caveat(client):
    client.post("/v1/demo/load")
    incident = client.post("/v1/incidents/analyze").json()[0]
    text = client.get(f"/v1/incidents/{incident['incident_id']}/report").text
    assert "Timeline" in text and "not proof" in text


def test_dashboard_serves_its_branding_and_interaction_assets(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "situational clarity" in page.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/polish.css").status_code == 200
