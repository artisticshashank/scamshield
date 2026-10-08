# ScamShield --- Detection Engine Implementation Plan

## Objective

Build the real ScamShield detection engine before connecting the final
UI.

The core pipeline:

``` text
URL / Message / QR
        ↓
URL Extraction
        ↓
Normalization & De-obfuscation
        ↓
Feature Extraction
        ↓
Rule Engine
        ↓
ML Classifier
        ↓
SHAP Explainability
        ↓
Threat Reputation
        ↓
Domain / DNS / SSL Intelligence
        ↓
Redirect Analysis
        ↓
Risk Fusion
        ↓
0–100 Risk Score
        ↓
Safe / Suspicious / Dangerous
        ↓
Forensic Explanation
```

------------------------------------------------------------------------

# Phase 1 --- Detection Core

## 1. URL Normalization

Implement:

-   URL parsing
-   scheme detection
-   hostname extraction
-   port extraction
-   path/query/fragment extraction
-   percent-decoding
-   lowercase normalization where appropriate
-   punycode detection
-   IP-address detection
-   URL canonicalization
-   suspicious encoding detection
-   malformed URL handling

### Output

``` json
{
  "original_url": "...",
  "normalized_url": "...",
  "scheme": "https",
  "hostname": "...",
  "port": 443,
  "path": "...",
  "query": "...",
  "fragment": "...",
  "is_ip_host": false,
  "is_punycode": false
}
```

------------------------------------------------------------------------

# 2. Feature Extraction

Create a consistent feature schema for both the rules and ML model.

## URL Features

-   URL length
-   hostname length
-   path length
-   query length
-   number of dots
-   number of hyphens
-   number of underscores
-   number of digits
-   number of special characters
-   number of subdomains
-   path depth
-   query parameter count
-   fragment length
-   percent-encoded character count
-   entropy
-   digit ratio
-   special-character ratio

## Security Features

-   HTTPS enabled
-   IP host
-   `@` symbol
-   double slash in path
-   punycode
-   suspicious TLD
-   excessive subdomains
-   suspicious port
-   URL shortening service
-   suspicious keywords
-   credential-related keywords
-   payment-related keywords
-   urgency-related keywords
-   brand names in hostname/path
-   possible brand impersonation
-   homoglyph similarity

------------------------------------------------------------------------

# 3. Rule Engine

Rules should produce structured evidence instead of only a numerical
score.

Example:

``` json
{
  "rule_id": "URL_IP_HOST",
  "severity": "high",
  "score": 18,
  "message": "The URL uses an IP address instead of a normal domain."
}
```

## Initial Rules

### High severity

-   Known malicious reputation
-   IP host combined with credential/payment keywords
-   Strong brand impersonation
-   Homoglyph/punycode brand impersonation
-   Dangerous redirect destination

### Medium severity

-   Very new domain
-   Excessive subdomains
-   Suspicious URL encoding
-   Suspicious TLD
-   URL shortener
-   Credential/payment keywords
-   Abnormal URL structure

### Low severity

-   Very long URL
-   High special-character ratio
-   High entropy
-   Unusual path depth
-   Missing HTTPS

Rules must be independently testable.

------------------------------------------------------------------------

# 4. ML Classifier

Start with a strong, explainable baseline.

## Model

Primary:

``` text
Character n-grams
        ↓
TF-IDF
        ↓
Logistic Regression
        ↓
Phishing probability
```

Also benchmark:

``` text
LightGBM / Gradient Boosting
```

Do not choose the more complicated model simply because it sounds more
advanced.

## Training requirements

Avoid random-only splitting.

Use:

-   training set
-   validation set
-   time-based test set
-   fresh manually collected test set

The fresh test set should contain:

-   known phishing URLs
-   legitimate URLs
-   brand impersonation
-   shortened URLs
-   newly registered-looking domains
-   tricky legitimate URLs
-   long legitimate URLs
-   internationalized domains

## Metrics

Report:

-   Precision
-   Recall
-   F1
-   ROC-AUC
-   False-positive rate
-   Detection latency
-   Zero-day/fresh-set recall

Do not claim unrealistic accuracy.

------------------------------------------------------------------------

# 5. SHAP Explainability

SHAP explains the ML model --- not the entire security system.

The UI should distinguish:

### ML explanation

Why the classifier predicted phishing.

Example:

``` text
Suspicious character patterns     +0.21
Credential-related tokens         +0.16
Abnormal URL structure            +0.13
Excessive path complexity         +0.09
Legitimate domain patterns        -0.04
```

### Security explanation

What the security engine objectively detected.

Example:

``` text
Domain registered recently
Brand impersonation detected
3 redirect hops
No reputation match
TLS certificate valid
```

Do not use an LLM for the MVP explanation layer.

------------------------------------------------------------------------

# 6. Risk Fusion Engine

Combine independent signals.

Initial architecture:

``` text
Rules
ML
Reputation
Domain Intelligence
Redirect Analysis
        ↓
Risk Fusion
        ↓
0–100
```

Suggested initial weighting:

``` text
Rules              30%
ML                  30%
Reputation          25%
Domain intelligence 15%
```

These are starting values, not permanent constants.

They should eventually be calibrated using validation data.

## Hard overrides

Known malicious reputation should be able to override a low ML score.

Example:

``` text
Known malicious URL
        ↓
DANGEROUS
```

A URL should not become safe simply because its character pattern
resembles legitimate URLs.

------------------------------------------------------------------------

# Phase 2 --- Threat Intelligence

## 7. Reputation

Integrate:

-   Google Safe Browsing
-   PhishTank
-   OpenPhish

Return:

``` json
{
  "source": "example_feed",
  "matched": true,
  "confidence": "high"
}
```

Do not expose API keys to the frontend.

------------------------------------------------------------------------

# 8. Domain Intelligence

Collect where available:

-   domain age
-   registrar
-   registration dates
-   nameservers
-   DNS records
-   IP address
-   ASN
-   country/region
-   certificate information

Important:

A new domain is a signal, not proof of maliciousness.

------------------------------------------------------------------------

# 9. DNS Intelligence

Check:

-   A
-   AAAA
-   CNAME
-   MX
-   NS
-   TXT

Detect:

-   unresolved domain
-   suspicious DNS configuration
-   rapidly changing infrastructure where data is available
-   private/internal IP resolution

------------------------------------------------------------------------

# 10. SSL/TLS Intelligence

Inspect:

-   certificate validity
-   expiration
-   issuer
-   hostname match
-   SANs
-   certificate chain

Important:

**HTTPS does not mean a website is safe.**

Treat valid TLS as supporting evidence only.

------------------------------------------------------------------------

# 11. Redirect Analysis

Follow redirects safely with a strict hop limit.

Example:

``` text
URL
 ↓
shortener
 ↓
tracking domain
 ↓
landing page
 ↓
phishing domain
```

Record every hop.

## SSRF protection

Never allow the redirect engine to access:

-   localhost
-   private IPv4 ranges
-   private IPv6 ranges
-   link-local addresses
-   cloud metadata endpoints
-   internal network services

No page rendering is required for the MVP.

------------------------------------------------------------------------

# Phase 3 --- Message Scanning

Input:

``` text
Your account has been suspended.
Verify immediately:
https://example.com/verify
```

Pipeline:

``` text
Message
 ↓
Extract every URL
 ↓
Scan each URL independently
 ↓
Aggregate results
 ↓
Return message-level risk
```

Example:

``` json
{
  "message_risk": 88,
  "urls_found": 2,
  "dangerous_urls": 1,
  "results": []
}
```

------------------------------------------------------------------------

# Phase 4 --- Unified Scan Result Contract

All interfaces should consume the same backend result structure.

``` json
{
  "scan_id": "...",
  "risk_score": 91,
  "verdict": "dangerous",
  "recommendation": "Do not open this link or enter credentials.",

  "ml": {
    "model": "url-ngram-logistic-regression",
    "phishing_probability": 0.947,
    "shap": []
  },

  "signals": [],

  "reputation": [],

  "domain": {},

  "dns": {},

  "tls": {},

  "redirects": [],

  "explanation": []
}
```

This contract should drive:

-   Scanner result page
-   Threat Forensics page
-   History
-   REST API
-   future browser extension
-   future mobile scanner

------------------------------------------------------------------------

# Phase 5 --- API

Build FastAPI only after the detection core works independently.

## Endpoints

``` text
POST /scan
POST /scan/message
GET  /scan/{scan_id}
GET  /health
```

The API should call the detection engine rather than contain detection
logic itself.

Architecture:

``` text
FastAPI
   ↓
Service Layer
   ↓
Detection Engine
   ├── Rules
   ├── ML
   ├── SHAP
   ├── Reputation
   ├── Domain Intel
   ├── DNS
   ├── TLS
   └── Redirects
```

------------------------------------------------------------------------

# Phase 6 --- Testing

Create a dedicated test suite.

## Unit Tests

Test every:

-   URL parser
-   feature extractor
-   rule
-   risk calculation
-   normalization function
-   SSRF protection function

## Integration Tests

Test:

``` text
URL → complete scan → result
```

## Adversarial Tests

Include:

-   IP URLs
-   `@` URLs
-   punycode
-   homoglyphs
-   URL encoding
-   nested redirects
-   shorteners
-   very long URLs
-   excessive subdomains
-   legitimate long URLs
-   legitimate payment URLs
-   legitimate login URLs
-   new domains
-   malformed URLs

------------------------------------------------------------------------

# Phase 7 --- Evaluation

Compare:

``` text
Rule-only
ML-only
Reputation-only
Rule + ML
Rule + ML + Reputation
Full ScamShield
```

Evaluate all of them on the same fresh test set.

The key question:

> Does the complete system detect threats that individual approaches
> miss while keeping false positives low?

This is the evidence needed to support the claim that ScamShield is
better than a basic phishing classifier.

------------------------------------------------------------------------

# Final Development Order

Do not build everything simultaneously.

``` text
01  Project structure
02  URL normalization
03  Feature extraction
04  Rule engine
05  Rule tests
06  ML dataset preparation
07  ML baseline
08  Model evaluation
09  SHAP
10  Risk fusion
11  Unified ScanResult
12  Reputation
13  Domain intelligence
14  DNS
15  TLS
16  Redirect analysis + SSRF protection
17  Message scanning
18  FastAPI
19  Connect existing UI
20  End-to-end testing
21  Benchmark against baselines
22  Fresh/zero-day evaluation
```

# Definition of Done

ScamShield is ready for a serious demo when:

-   [ ] A URL can be normalized safely
-   [ ] Features are extracted consistently
-   [ ] Rules produce structured evidence
-   [ ] ML produces calibrated phishing probability
-   [ ] SHAP explains ML predictions
-   [ ] Risk fusion produces a 0--100 score
-   [ ] Safe / Suspicious / Dangerous verdicts work
-   [ ] Reputation sources are integrated
-   [ ] Domain/DNS/TLS intelligence works
-   [ ] Redirects are analyzed safely
-   [ ] SSRF protection is tested
-   [ ] SMS/message URLs are extracted and scanned
-   [ ] API returns the unified result contract
-   [ ] Threat Forensics UI consumes real backend data
-   [ ] False-positive rate is measured
-   [ ] Fresh/zero-day performance is measured
-   [ ] All major components have automated tests

## Core Principle

> **Do not make ScamShield look intelligent. Make every part of its
> intelligence measurable, explainable, and testable.**
