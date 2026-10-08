# External Intelligence Fixture Report

## Scope

This phase added deterministic offline fixture coverage for reputation,
domain intelligence, and redirect analysis. No live providers, API keys,
DNS, RDAP, TLS connections, or redirect targets are used by the fixture
tests.

Risk Fusion behavior, thresholds, weights, the ML artifact, and
`Dataset.csv` were not modified. EVIDENCE_AWARE semantics remain locked.
SHAP remains explanatory-only and is not included in risk scoring.

## Fixture inventory

### Reputation

- Google Safe Browsing: confirmed malicious and confirmed clean payloads
- PhishTank: confirmed malicious and confirmed clean payloads
- OpenPhish: confirmed malicious and confirmed clean feed payloads
- Provider disagreement: malicious and clean provider results
- Provider unavailable: explicit unavailable result
- Provider timeout: `TimeoutError` mapped to unavailable
- Malformed response: explicit malformed result
- HTTP/provider error: explicit failed result
- Rate limiting: explicit rate-limited result
- Normalized URL and API-key non-disclosure checks

Fixture data is defined in
[external_intelligence.py](../tests/fixtures/external_intelligence.py).

### Domain intelligence

- DNS A, AAAA, MX, NS, and CNAME records
- Private, link-local, loopback, documentation, and special IP detection
- RDAP registration date and domain-age derivation
- Expired TLS certificate metadata
- TLS hostname mismatch failure
- DNS/RDAP/TLS timeout behavior
- Malformed RDAP response behavior
- Explicit assertion that fixture collection does not connect to resolved IPs

### Redirect analysis

- No redirect
- One redirect
- Multiple redirects
- Cross-domain redirect through existing redirect tests
- Shortener detection through existing feature integration
- Redirect loop
- Hop and chain-entry limits
- Private and localhost destinations
- Cloud metadata destination (`169.254.169.254`)
- DNS rebinding with mixed public/private answers
- Timeout
- Malformed `Location`
- Redirect signal integration with Risk Fusion

## Expected versus actual normalized behavior

| Fixture area | Expected normalized behavior | Actual |
|---|---|---|
| Google malicious | `AVAILABLE`, malicious `true`, score `100` | Pass |
| Google clean | `AVAILABLE`, malicious `false`, score `0` | Pass |
| PhishTank malicious | `AVAILABLE`, malicious `true`, phishing category | Pass |
| PhishTank clean | `NOT_FOUND`, malicious `false`, score `0` | Pass |
| OpenPhish malicious | `AVAILABLE`, malicious `true`, phishing category | Pass |
| OpenPhish clean | `NOT_FOUND`, malicious `false`, score `0` | Pass |
| Provider disagreement | Aggregate malicious if any provider confirms malicious | Pass |
| Unavailable/timeout | No score; excluded from fusion | Pass |
| Malformed/provider error | Explicit malformed/failed status; no score | Pass |
| DNS private/special IP | Available result with explicit private/special IP evidence | Pass |
| RDAP registration | Available result with deterministic age signal | Pass |
| TLS expiry | Available result with expired-certificate signal | Pass |
| TLS hostname mismatch | Failed result, hostname not verified | Pass |
| Redirect SSRF destination | Blocked before request callback | Pass |
| Redirect timeout | Explicit timeout result | Pass |
| Redirect malformed location | Failed result with blocked chain entry | Pass |

## Fusion behavior

Fixture tests verify that:

- Available reputation, domain, and redirect signals participate in fusion.
- Unavailable signals are excluded rather than interpreted as clean.
- Failed signals are excluded rather than interpreted as clean.
- Provider disagreement remains malicious when any provider confirms malicious.
- Empty rule evidence preserves the locked EVIDENCE_AWARE behavior.
- SHAP has no fusion score contribution.
- Serialized results remain JSON-compatible.

## Security and SSRF coverage

The redirect fixtures verify that:

- Resolved private, loopback, link-local, multicast, unspecified,
  documentation, and metadata addresses are blocked.
- All resolved addresses are checked before any request callback is invoked.
- A DNS-rebinding-style mixed public/private response is blocked.
- Localhost and unsupported schemes are rejected before requests.
- Redirect hops and chain entries are bounded.
- Malformed redirect destinations are rejected.
- Response bodies are not stored.

The domain fixtures separately verify that DNS collection does not connect to
returned addresses.

## Test results

### Fixture-focused suite

Command:

```text
pytest tests/test_external_intelligence_fixtures.py \
       tests/test_reputation.py \
       tests/test_domain_intelligence.py \
       tests/test_redirect_analysis.py -q
```

Result:

```text
58 passed in 1.26s
```

### Complete backend suite

Command:

```text
pytest tests -q
```

Result:

```text
188 passed, 1 failed in 3.26s
```

The only failure is the previously known, unrelated SHAP environment-sensitive
test:

```text
tests/test_shap_explainability.py::test_positive_and_negative_attributions_are_real_shap_values
```

The failure is the assertion that the selected SHAP features include a
negative attribution. No SHAP code was changed in this phase.
