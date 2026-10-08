# ScamShield V1 Product Foundation — Phase 0 Audit

**Audit status:** Complete  
**Audit scope:** Existing repository only; no production implementation changes made  
**Audit date:** 2026-10-08

## Executive summary

ScamShield currently consists of a Next.js frontend and a modular FastAPI
backend. The detection engine, frozen model artifact, local browser history,
QR decoding, URL/message scanning, forensic rendering, CORS policy, redirect
analysis, and TLS SSRF protections already exist. There is no existing
Supabase integration, authentication, PostgreSQL persistence, server-side user
session handling, or rate-limiting layer.

The current scanner is guest-like only because results are stored in browser
storage. It is not an authenticated guest allowance: there is no trusted
server-side identity or quota enforcement.

The requested V1 product work can be added around the existing scan pipeline,
but it must not rewrite or retune detection behavior.

## A. What already exists

### Repository and tooling

- Frontend: Next.js `16.4.0`, React `19.3.0`, TypeScript, Tailwind CSS,
  ESLint, npm lockfile.
- Backend: FastAPI with Python package requirements in
  `backend/requirements.txt`.
- Package managers: npm for the frontend; pip/venv-based Python tooling for
  the backend.
- Frontend scripts: `dev`, `build`, `start`, `lint`, and the
  scan-selection regression script.
- Backend tests: pytest tests covering normalization, feature extraction,
  rules, ML, SHAP, fusion, message scanning, reputation, domain intelligence,
  redirects, API/service behavior, training, and evaluation.
- No repository-level deployment manifest or Supabase configuration was found.
- No checked-in `.env` or `.env.example` file was found. The frontend reads
  `NEXT_PUBLIC_SCAMSHIELD_API_URL` when present and otherwise uses
  `http://localhost:8000`.

### Frontend routes and flow

Existing App Router pages:

- `/` — scanner UI for URL and raw-message input, plus QR image intake.
- `/history` — browser-local scan history.
- `/forensics` — selected scan result and evidence report.
- `/api-docs` — static API documentation UI.
- `/about` — static product information.

There is currently no `/scanner` route. The existing scanner route is `/`.

The scanner sends URL, message, and decoded QR input to:

```text
POST http://localhost:8000/scan
```

It stores successful responses locally and navigates to `/forensics`.

### QR workflow

The scanner has a real image file input accepting PNG, JPEG, and WebP. QR
payloads are decoded locally with `jsqr`; decoded text is passed into the
existing URL scan path. The frontend does not navigate to the decoded URL.

### Current result storage

`frontend/src/lib/scamshield.ts` stores:

- display history in `localStorage["scamshield.scan_history"]`;
- individual records in `localStorage["scamshield.scan_records"]`;
- a latest-result compatibility fallback in
  `sessionStorage["scamshield.latest_scan"]`.

Forensics selection supports an explicit `scan_id` query parameter and gives it
precedence over the latest-result fallback. This storage is browser-local,
mutable by the user, and not suitable as an authoritative persistent history.

### Backend API and security

Existing FastAPI endpoints:

- `GET /health`
- `POST /scan`

`POST /scan` accepts an input string and `input_type` (`auto`, `url`, or
`message` behavior through service detection). Invalid input is rejected with
HTTP 422 and an explicit error body.

Existing security controls include:

- bounded input and message extraction limits;
- scoped local CORS origins (`localhost:3000` and `127.0.0.1:3000`);
- redirect hop, timeout, URL, header, and chain limits;
- shared SSRF IP policy;
- DNS resolution validation and DNS-rebinding protection;
- validated-IP connections while preserving hostname SNI/certificate checks;
- no frontend-controlled proxy, header, or provider configuration;
- no URL opening or page execution during QR scanning.

No backend rate limiter was found.

## B. What can be reused

1. **Existing scan service:** Keep `ScanService.scan()` as the single detection
   entry point. New authenticated or guest flows should call the existing
   backend API rather than duplicate detection logic.
2. **Existing scan response contract:** Persist the existing URL and message
   result fields, including scan IDs, verdicts, scores, evidence, signal
   availability, and metadata.
3. **Existing frontend result mapping:** Reuse the forensic report and
   scan-selection behavior. Authenticated history should feed the same
   response shape.
4. **Existing local guest UX:** The current scanner, QR decoder, loading/error
   states, and forensics navigation can remain the presentation baseline.
5. **Existing backend CORS and SSRF controls:** Extend configuration only where
   required by the deployment model; do not weaken these controls.
6. **Existing tests and deterministic fixtures:** Add product/auth/database
   tests around the current tests without changing detection fixtures or model
   expectations.
7. **Existing model artifact loading:** API inference already loads the frozen
   artifact and does not train during requests.

## C. What must be added

The V1 product foundation requires new infrastructure around the frozen engine:

1. **Supabase client configuration**
   - browser client for frontend auth/session use;
   - server-side client or verified-token integration for protected operations;
   - documented public environment variables and secret handling.
2. **Authentication**
   - login, signup, logout, and password-reset flows;
   - protected session hydration and route behavior;
   - automatic continuation of a pending scan after authentication.
3. **Supabase PostgreSQL schema**
   - user-owned scan records;
   - guest allowance/claim state;
   - timestamps and scan metadata;
   - indexes required for user history queries.
4. **Row Level Security**
   - authenticated users may access only their own records;
   - guest allowance cannot be increased by client-controlled fields;
   - service-role operations, if any, remain server-only.
5. **Trusted guest allowance enforcement**
   - server-side identity or abuse-resistant anonymous identity;
   - atomic allowance consumption;
   - explicit behavior for unauthenticated repeat use and failures.
6. **Persistent history integration**
   - authenticated history reads from Supabase;
   - local storage remains a cache or migration source, not the authority;
   - scan detail lookup validates ownership.
7. **Auth-aware frontend routing**
   - public landing page;
   - guest-first scanner entry;
   - auth pages and pending-scan continuation;
   - authenticated history and detail access.
8. **Production configuration and tests**
   - environment validation;
   - auth/session, RLS, guest allowance, ownership, and continuation tests;
   - deployment configuration and operational documentation.
9. **Likely backend boundary**
   - a secure persistence/auth integration layer or server-side API endpoints
     must be selected before implementation;
   - the current `/scan` endpoint does not authenticate callers or persist
     results.

## D. What must not be changed

The detection engine is explicitly frozen. Product work must not modify:

- URL normalization;
- feature extraction;
- deterministic rule definitions or weights;
- character n-gram TF-IDF configuration;
- Logistic Regression model or model artifact;
- SHAP computation or explanation semantics;
- risk-fusion weights, thresholds, or verdict boundaries;
- message URL extraction and maximum-risk aggregation;
- reputation, DNS, RDAP, TLS, redirect, or SSRF policy behavior;
- CORS security restrictions without a documented deployment requirement;
- datasets, training/evaluation outputs, or benchmark claims.

The existing Threat Forensics experience should be preserved, not redesigned.
Any response-shape changes must remain backward-compatible with the current
frontend mapping or be introduced through an explicit adapter.

## Current product gaps

| Capability | Current state | V1 requirement |
|---|---|---|
| Public landing page | Scanner is currently the root route | Add public landing experience while preserving scanner |
| Guest scanning | Browser-local, no trusted allowance | Secure server-enforced guest allowance |
| Authentication | Not present | Supabase Auth flows and session handling |
| Database | Not present | Supabase PostgreSQL persistence |
| RLS | Not present | User ownership policies |
| Scan history | Local storage only | Persistent authenticated history |
| Pending scan continuation | Not present | Resume after authentication |
| API auth | `/scan` is unauthenticated | Define and implement secure boundary without changing detection |
| Rate limiting | Not present | Add abuse controls appropriate to guest/auth flows |
| QR scanning | Implemented client-side | Preserve and associate results with scan ownership |

## Recommended implementation order

1. Define the Supabase schema, ownership model, guest allowance semantics, and
   trust boundaries.
2. Add environment validation and Supabase clients without changing scan
   behavior.
3. Implement authentication and session hydration.
4. Add server-enforced guest allowance and pending-scan continuation.
5. Persist scan results and integrate authenticated history/detail views.
6. Add RLS, abuse controls, and security-focused tests.
7. Run the existing frontend and complete backend suites, then add product
   integration tests.

No product implementation should begin until the guest allowance semantics and
the authenticated/server-side API boundary are explicitly decided.
