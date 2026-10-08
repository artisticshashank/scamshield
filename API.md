# API

The FastAPI application is in `backend/src/api/app.py`.

## `GET /health`

Returns service status and component availability, including normalization,
rules, ML, SHAP, reputation, domain intelligence, and redirect analysis.

## `POST /scan`

Request JSON:

```json
{
  "input": "https://example.com",
  "input_type": "url"
}
```

`input` is a non-empty string. `input_type` accepts `url`, `message`, or
`auto`. URL scans return a unified `ScanResult` containing scan ID, original
and normalized URL data, verdict, risk score, recommendation, rule evidence,
ML/SHAP results, external signal results, score breakdown, metadata, and
timestamp. Message scans return extracted deduplicated URLs, one result per
URL, maximum-risk aggregation, verdict, recommendation, and metadata.

Invalid JSON, invalid input type, malformed URLs, and service limit violations
return HTTP 422 with an `error` field. The API does not expose server-side
history, proxy configuration, or provider configuration endpoints.
