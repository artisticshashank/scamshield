# ScamShield

ScamShield is a modular URL and message threat-detection prototype. It
normalizes input, extracts URL features, evaluates deterministic rules, runs a
frozen character n-gram TF-IDF plus Logistic Regression classifier, produces
real SHAP explanations, and combines available evidence with evidence-aware
risk fusion.

It supports URL scans and messages containing multiple HTTP(S) URLs. Missing
reputation, domain, or redirect signals remain explicitly unavailable rather
than being treated as clean.

## Security properties

Redirect and TLS analysis validate resolved addresses against shared SSRF
policy, block private/loopback/link-local/metadata and other special ranges,
limit redirects, and preserve the original hostname for TLS SNI and
certificate verification. The API does not accept arbitrary proxy or outbound
header configuration.

## Structure

- `backend/src/core/`: detection pipeline and intelligence collectors
- `backend/src/api/`: FastAPI application
- `backend/tests/`: deterministic unit and integration tests
- `backend/data/`: datasets and evaluation reports
- `backend/artifacts/`: frozen model and generated evaluation artifacts
- `frontend/src/`: Next.js scanner, history, and forensic views

## Local checks

Backend tests use the configured Python 3.11 interpreter:

```text
cd backend
PYTHONPATH=src python -m pytest tests -q
```

Frontend scripts are defined in `frontend/package.json`:

```text
cd frontend
npm run lint
npx tsc --noEmit
npm run build
```
