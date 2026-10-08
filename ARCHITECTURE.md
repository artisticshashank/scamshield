# Architecture

## Detection pipeline

Input enters URL extraction (for messages), normalization, feature extraction,
the deterministic rule engine, the frozen ML classifier, SHAP explainability,
available external-intelligence collectors, and evidence-aware risk fusion.
The result is a serializable `ScanResult`.

- **Normalization:** parses and canonicalizes HTTP(S) URLs, detects IP hosts,
  punycode, encoding, ports, paths, queries, and malformed input.
- **Feature extraction:** produces structural, lexical, encoding, keyword,
  brand, shortener, and URL-statistic features.
- **Rules:** returns structured `RuleEvidence`, not only a score.
- **ML:** character n-gram TF-IDF `(3,5)` with Logistic Regression. Training is
  separate from API inference.
- **SHAP:** uses the actual fitted model and is explanatory-only; it never
  changes risk scoring.
- **Risk fusion:** combines available signals using locked EVIDENCE_AWARE
  semantics and locked thresholds.

## External intelligence

Reputation has provider abstractions for Google Safe Browsing, PhishTank, and
OpenPhish. Domain intelligence covers DNS, RDAP registration data, and TLS
metadata. Redirect analysis is bounded and SSRF-aware. Providers and live
network signals are unavailable unless configured; deterministic fixtures test
their normalized contracts offline.

## Message scanning

Messages are length-limited, HTTP(S) URLs are extracted and deduplicated, each
URL is scanned independently, and the maximum URL risk is used for the
message-level result.

## API and frontend

FastAPI exposes `POST /scan` and `GET /health`. The Next.js frontend submits URL
or message input to `/scan`, stores results in browser-local storage, and
renders the selected result in the forensic view. History is local-browser
history; there is no server-side history endpoint.
