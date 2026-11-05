# RepoSentinel

**Predictive Software Supply Chain Risk Intelligence Platform** — an engineering foundation for package intelligence focused initially on the Python ecosystem (PyPI).

RepoSentinel is designed as a decision-support layer, not a replacement for vulnerability scanners. It separates confirmed security findings from any future-risk estimates.

## Current milestone: data-ingestion foundation

- FastAPI service with health, ingestion, and package-inspection endpoints
- PostgreSQL persistence via SQLAlchemy
- PyPI project metadata and release ingestion
- OSV advisory ingestion
- Bounded HTTP response handling, request timeouts, and input validation
- Docker Compose for repeatable local development

> This repository is an early development milestone, not a production-ready security product. The 90-day prediction horizon is a research hypothesis and is not yet validated.

## Architecture

```text
PyPI JSON API ----\
                   -> FastAPI ingestion -> PostgreSQL
OSV API ----------/          |
                              -> package/release/advisory records

Planned: deps.dev dependency graph, historical feature snapshots,
temporal ML evaluation, explainability, Streamlit dashboard.
```

## Run locally

Requirements: Python 3.11+ and Docker Desktop with Docker Compose.

1. Copy `.env.example` to `.env`.
2. Run `docker compose up --build`.
3. Open [API docs](http://localhost:8000/docs).
4. Check [health](http://localhost:8000/health).

Ingest a package:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/ingest/pypi/requests"
```

Inspect a package:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/packages/requests"
```

## API

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | API/database health |
| POST | `/ingest/pypi/{package_name}` | Fetch PyPI metadata and OSV package advisories |
| GET | `/packages/{package_name}` | Read stored package metadata |

## Data sources

- [PyPI JSON API](https://docs.pypi.org/api/json/)
- [OSV API](https://google.github.io/osv.dev/api/)
- [deps.dev API](https://docs.deps.dev/) — planned for dependency graph ingestion

## Important limitations

- Advisory ingestion is package-level in this initial milestone. It does **not** yet prove that a particular installed version is affected.
- Version-range normalization and matching are a required next step.
- No package code, build script, or installation script is executed.
- The ingestion API has no authentication/rate limiting yet; do not expose it publicly as-is.
- Future-risk prediction will only be implemented after historical label feasibility and chronological evaluation are established.

## Roadmap

1. Version-aware OSV affected-range normalization
2. Dependency graph ingestion and exposure analysis
3. Reproducible historical ETL and feature snapshots
4. Temporal dataset construction and leakage-safe validation
5. Baseline models, calibration, and explainability
6. Streamlit risk-intelligence dashboard
7. Authentication, tests, CI, observability, and deployment hardening

## License

No license has been selected yet. All rights remain with the repository owner.
