# RepoSentinel

**Software Supply Chain Risk Intelligence** for the Python package ecosystem.

RepoSentinel is a decision-support layer for inspecting Python package metadata and published vulnerability advisories. It is not a replacement for security scanners.

## Live application

- Dashboard: https://reposentinel.onrender.com/
- API docs: https://reposentinel.onrender.com/docs
- Health: https://reposentinel.onrender.com/health

## Current capabilities

- Premium dark-mode dashboard
- Live PyPI package metadata lookup
- OSV advisory lookup
- Optional package-version query for OSV
- Input validation, request timeouts, response-size limits
- Docker-based Render deployment

## Run locally

Python 3.11+:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://localhost:8000 and http://localhost:8000/docs.

## API

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Dashboard |
| GET | `/api` | API metadata |
| GET | `/health` | Health check |
| GET | `/packages/{package_name}` | PyPI project metadata |
| GET | `/packages/{package_name}/advisories?version=x.y.z` | OSV advisories |

## Important limitations

- This is an early product milestone, not a production-ready security platform.
- Advisory presence alone does not establish that a particular release is affected; affected-range matching is a required next step.
- No 90-day predictive model has been trained or validated. The horizon remains a research hypothesis.
- The dashboard does not fabricate portfolio-wide counts or risk scores.
- Authentication, rate limiting, persistent storage, dependency graph analysis, tests, and operational monitoring remain planned.
- No package code or installation scripts are executed.

## Data sources

- [PyPI JSON API](https://docs.pypi.org/api/json/)
- [OSV API](https://google.github.io/osv.dev/api/)
- [deps.dev](https://docs.deps.dev/) — planned
- [OpenSSF Scorecard](https://scorecard.dev/) — planned

## Roadmap

1. Version-aware OSV affected-range matching
2. Dependency graph ingestion and transitive exposure
3. PostgreSQL persistence and reproducible historical ETL
4. Leakage-safe temporal dataset and model evaluation
5. Calibrated ML baselines and explainability
6. Authentication, automated tests, CI, and production hardening

No license has been selected; all rights remain with the repository owner.
