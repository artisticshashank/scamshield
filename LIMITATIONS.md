# Limitations

- The shipped classifier is a frozen baseline and is not calibrated by claim;
  its internal test performance does not guarantee external performance.
- PhishVN showed a major distribution-shift limitation (strict-clean ML
  ROC-AUC 0.508767); PhishBench was materially stronger (0.880242).
- `Dataset.csv` has no timestamp coverage, so chronological evaluation was not
  available. Domain-grouped splitting was used.
- Reputation, DNS/RDAP/TLS, and redirect integrations are explicitly
  unavailable when not configured. External-intelligence fixture tests are
  deterministic and offline; they are not live-provider validation.
- No zero-day, universal-detection, guaranteed-accuracy, or production
  readiness claim is made.
- Frontend history is browser-local and the frontend assumes the backend is
  reachable at its configured local API base URL.
- Known non-blocking backend warnings are three SHAP plotting-library
  `PendingDeprecationWarning`s. Frontend lint is expected to be rerun as part
  of final verification.
