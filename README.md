# Sentinel SOC — Threat Detection & Incident Triage

Sentinel is an explainable SOC workbench that correlates authentication, privilege, API, cloud, data-access, and malware events into prioritized incidents. It gives analysts a timeline, explicit rule findings, a risk score, and a draft containment action that cannot run until approved.

![CI](https://github.com/DivyanBabbar/sentinel-soc/actions/workflows/ci.yml/badge.svg)

## Capabilities

- Typed security-event ingestion, single or batch
- SQLite event store with actor and source-IP time indexes
- Correlation by actor or IP within a bounded time window
- Transparent scoring rules for failed logins, password-spray patterns, privilege changes, suspicious API calls, cloud policy changes, elevated data access, and malware indicators
- Incident queue with severity, evidence timeline, findings, and recommended action
- Markdown incident report export
- Analyst approval gate and idempotent simulated containment
- Responsive SOC dashboard, FastAPI/OpenAPI docs, Docker, pytest, Ruff, CodeQL

## Run it

```bash
git clone https://github.com/DivyanBabbar/sentinel-soc.git
cd sentinel-soc
python -m venv .venv
# Activate the environment, then:
pip install -e '.[dev]'
sentinel-soc
```

Open <http://127.0.0.1:8000>, select **Load attack simulation**, then review the correlated password-spray and privilege-escalation incident. Try the approval step and simulated containment. API reference is available at `/docs`.

### 2–5 minute demo

1. Select **Load attack simulation** to ingest eight synthetic security events.
2. Review the incident score, password-spray finding, and correlated event timeline.
3. Approve the recommended containment action and run the simulation.
4. Open the incident report to inspect its evidence and analyst caveat.

The workflow runs locally without provider credentials. Copy `.env.example` to `.env` only if you want to change `SENTINEL_DATA_DIR`.

Docker: `docker compose up --build`.

## API

- `POST /v1/events` ingest one event
- `POST /v1/events/batch` ingest 1–1,000 events
- `POST /v1/demo/load` add synthetic attack signals
- `POST /v1/incidents/analyze` correlate recent events into incidents
- `GET /v1/incidents` list detections
- `GET /v1/incidents/{id}/report` download an evidence-based Markdown report
- `POST /v1/incidents/{id}/contain/approve` record analyst approval
- `POST /v1/incidents/{id}/contain/execute` simulate the approved action

## Scoring and limitations

Rule scores are transparent prioritization signals, not calibrated probabilities and not proof of compromise. Thresholds and event weights are illustrative; calibrate them with labeled, tenant-specific data before operational use. Correlation uses actor/IP and a fixed time window. It does not yet enrich threat intelligence, resolve identities, apply asset criticality, or ingest vendor-specific SIEM formats.

Containment is simulation-only: this repository does not block IPs, disable accounts, isolate hosts, or call cloud APIs. The API has no authentication or tenant isolation. Keep it on localhost or a trusted development network. Before production, add identity and access controls, encrypted transport, audit retention, secret management, rate limits, source adapters, and tested response connectors with least privilege.

## Configuration

`SENTINEL_DATA_DIR` controls local SQLite storage and defaults to `data`.

## Development

```bash
pip install -e '.[dev]'
ruff check .
ruff format --check .
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md). MIT licensed.
