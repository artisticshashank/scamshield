# ScamShield Final Project Status

## COMPLETED

- Modular URL/message detection pipeline with normalization, features, rules,
  frozen TF-IDF plus Logistic Regression inference, SHAP explanations, and
  evidence-aware risk fusion.
- FastAPI `/scan` and `/health` endpoints.
- Frontend scanner now submits to `/scan`, stores the returned result locally,
  and renders backend-generated forensic data instead of fabricated static
  findings.
- Deterministic reputation, domain-intelligence, and redirect fixtures.
- SSRF-safe redirect analysis and TLS intelligence. The TLS SSRF/DNS-rebinding
  finding was fixed by resolving, validating every address, connecting only to
  a validated public IP, and retaining the original hostname for SNI and
  certificate verification.
- Regression tests for unsafe TLS resolutions, mixed DNS answers, DNS failure,
  timeout, validated-IP connection, and SNI preservation.

## SECURITY FIX STATUS

The MEDIUM-severity TLS intelligence SSRF/DNS-rebinding vulnerability is
**FIXED**. Unsafe resolved addresses result in zero outbound connection
attempts. The focused domain-intelligence suite passed with `23 passed`.

## TEST RESULTS

Complete backend suite:

```text
202 passed, 0 failed, 0 skipped, 3 warnings in 3.40s
```

The warnings are the previously known SHAP plotting-library
`PendingDeprecationWarning`s.

## FINAL INTEGRATION VERIFICATION

- Frontend API integration: PASS. URL and message requests use `POST /scan`.
- Invalid API responses return to the scanner with an error message.
- Loading state is represented by the existing scanning state.
- URL and message results are persisted in browser-local history.
- History selection opens the selected forensic result.
- Message forensic details list every backend-extracted URL and result.
- Frontend TypeScript: PASS (`npx tsc --noEmit`, exit code 0).
- Frontend production build: PASS (`npm run build`, exit code 0).
- Frontend lint: PASS, 0 errors and 3 warnings (`npm run lint`, exit code 0).
  The warnings are unused icon imports in existing static pages.
- Frontend typecheck: PASS (`npx tsc --noEmit`, exit code 0).
- Frontend production build: PASS (`npm run build`, exit code 0).
- Documentation: COMPLETE. Root `README.md`, `ARCHITECTURE.md`,
  `THREAT_MODEL.md`, `MODEL_CARD.md`, `EVALUATION.md`, `API.md`, and
  `LIMITATIONS.md` now describe the implemented system and limitations.
- Security: PASS. TLS SSRF/DNS rebinding: FIXED.

The backend warnings remain the three known SHAP plotting-library
`PendingDeprecationWarning`s. No unsupported accuracy or zero-day claims are
made.

## FROZEN ARTIFACTS

This security fix did not modify `Dataset.csv`, the trained ML artifact,
production thresholds, fusion weights, SHAP scoring behavior, or frontend
detection semantics.

## KNOWN LIMITATIONS

- External evaluation documents a material distribution shift, including weak
  transfer to PhishVN. No model tuning or benchmark changes were made.
- Reputation and some domain/redirect signals remain explicitly unavailable
  when providers or live collection are not configured.
- Browser history is local to the current browser; no backend history endpoint
  exists.
- The project does not claim zero-day detection, universal detection, guaranteed
  accuracy, or production readiness.

## BLOCKED / NOT CLAIMED

- No live provider or suspicious-URL scans were performed for this fix.
- No retraining, threshold tuning, fusion-weight tuning, dataset modification,
  or model research was performed.

## OPTIONAL FUTURE WORK

- Add authenticated server-side scan history if persistence is required.
- Run frontend lint/build checks in the configured Node environment.
- Continue independent security review before any production deployment.
