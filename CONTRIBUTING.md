# Contributing

Add tests for new detections, scoring, or response behavior. Document rule rationale and false-positive considerations. Keep fixtures synthetic; do not submit real customer logs, personal data, credentials, or indicators under embargo.

Run `pip install -e '.[dev]'`, `ruff check .`, and `pytest`. Response connectors require an explicit threat model, least privilege, auditability, and documented approval semantics.
