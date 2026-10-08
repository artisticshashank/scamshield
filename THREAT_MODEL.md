# Threat Model

## Assets and inputs

The system receives attacker-controlled URLs and message text. It must protect
the host running intelligence collectors, model artifacts, provider
credentials, and the integrity of detection results.

## Threats and mitigations

- **Phishing and scam URLs:** normalization, lexical/structural features,
  deterministic rules, ML inference, and explanatory SHAP output provide
  layered analysis.
- **SSRF:** redirect and TLS collectors resolve addresses explicitly and block
  private, loopback, link-local, multicast, unspecified, metadata, mapped, and
  other special ranges.
- **DNS rebinding:** requests connect to an already validated resolved IP;
  TLS retains the original hostname for SNI and certificate verification.
- **Redirect abuse:** hop, chain, URL, header, timeout, loop, and destination
  limits are enforced; response bodies are not executed or retained.
- **Malformed or oversized input:** URL normalization, Pydantic request
  validation, message limits, and service limits reject invalid input.
- **Proxy/header injection:** the API request model does not expose proxy or
  caller-controlled outbound headers.
- **Secrets and API keys:** provider credentials are configuration concerns and
  are not accepted from frontend scan payloads or exposed in scan results.

The system is a detection prototype and does not claim complete protection
against every attack or production readiness.
