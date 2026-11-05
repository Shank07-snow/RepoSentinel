# RepoSentinel

**Predictive Software Supply Chain Risk Intelligence Platform** for the Python package ecosystem.

RepoSentinel is designed as a decision-support layer, not a replacement for vulnerability scanners. It keeps confirmed advisory data separate from any future-risk estimates.

> **Status:** early API foundation. No predictive model is currently trained or validated. The proposed 90-day horizon remains a research hypothesis.

## What works in this milestone

- FastAPI service with interactive OpenAPI documentation
- Live PyPI package metadata lookup
- OSV advisory lookup, optionally filtered by package version
- Input validation, upstream timeouts, bounded response sizes, and safe error handling
- Docker deployment configuration and Render blueprint

## Architecture direction

```text
PyPI JSON API ─────┐
                  ├── FastAPI ingestion/API ── PostgreSQL (next milestone)
OSV API ──────────┘             │
                                └── package intelligence API
                                      │
                              Streamlit dashboard (planned)
```

## Run locally

Python 3.11+ is recommended.

```bash
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:
- API documentation: http://localhost:8000/docs
- Health check: http://localhost:8000/health

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Service metadata |
| GET | `/health` | Health check |
| GET | `/packages/{package_name}` | Current PyPI project metadata |
| GET | `/packages/{package_name}/advisories` | OSV advisories; optional `?version=x.y.z` |

Example:
```bash
curl http://localhost:8000/packages/requests
curl "http://localhost:8000/packages/requests/advisories?version=2.31.0"
```

## Deployment

The repository includes a `Dockerfile` and `render.yaml`. To deploy on Render, create a new **Web Service** from this GitHub repository and select the Blueprint option if prompted. Render will build the Docker image and use `/health` as its health check.

Do not expose this early API publicly for sensitive workloads. Authentication, rate limiting, persistence, observability, and production hardening are still pending.

## Data sources

- [PyPI JSON API](https://docs.pypi.org/api/json/)
- [OSV API](https://google.github.io/osv.dev/api/)
- [deps.dev](https://docs.deps.dev/) — planned dependency graph source
- [OpenSSF Scorecard](https://scorecard.dev/) — planned project health signals

## Research and engineering roadmap

1. Version-aware OSV affected-range normalization
2. Dependency graph ingestion and transitive exposure analysis
3. Historical ETL and reproducible feature snapshots
4. Temporal dataset construction and leakage-safe label validation
5. Baseline models, calibration, and explainability
6. Streamlit risk-intelligence dashboard
7. PostgreSQL persistence, tests, CI, authentication, and observability

## Security principles

- Never execute package code, build scripts, or installation scripts.
- Treat upstream data as untrusted input.
- Keep network timeouts and response-size limits.
- Add SSRF protections before accepting user-supplied repository URLs.

## License

No license has been selected. All rights remain with the repository owner.
