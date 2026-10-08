# ScamShield Security Notes

## TLS intelligence SSRF finding

- **Severity:** MEDIUM
- **Status:** FIXED
- **Component:** `backend/src/core/domain_intelligence.py`

The TLS collector now resolves the hostname with `socket.getaddrinfo()` through
the redirect subsystem's shared resolver, validates every returned address with
the existing `blocked_ip_reason` policy, and fails closed for unsafe or empty
resolution results. It connects only to the validated public IP address. The
original hostname is retained as the TLS SNI name, so normal certificate
hostname verification remains enabled.

The policy covers loopback, private and unique-local ranges, link-local,
multicast, unspecified, documentation and other special ranges already blocked
by redirect analysis, including IPv4-mapped addresses and cloud metadata
addresses.

Regression coverage proves that unsafe and mixed DNS results cause zero socket
connection attempts, DNS failures and timeouts remain explicit, and safe
resolution uses the validated IP while preserving the original SNI hostname.

## Scope

Redirect analysis also applies bounded hop limits, loop detection, destination
IP validation, DNS-rebinding protection, and response-header limits. The API
does not accept caller-controlled proxy settings or outbound request headers.

This document records implemented controls; it is not a claim of production
readiness or complete security assurance.
