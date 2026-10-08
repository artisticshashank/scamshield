# Validation-Only Risk Fusion Strategy Comparison

No production code, weights, thresholds, artifact, or dataset was modified. The TEST partition was not used.

Validation partition: 23,320 samples (23,227 benign, 93 malicious), domain-grouped split, seed 42. Primary threshold: 30. ML reference threshold: 20.

## Candidate definitions

- **CONDITIONAL_RULE_ADJUSTMENT:** ML base plus 0.25*rule when evidence exists; capped at 100; no evidence adds nothing.
- **CONFIGURED_WEIGHT_NO_RENORMALIZATION:** 0.30*ML + 0.30*rule; fixed denominator 1.0, unavailable 0.40 weight contributes neutral zero.
- **CURRENT:** (ML + rule)/2; available 0.30/0.30 weights renormalize to 50/50.
- **EVIDENCE_AWARE:** ML unchanged when no rule fires; current equal blend when rule evidence exists.
- **ML_DOMINANT_NO_RULE:** ML unchanged when no rule fires; 0.70*ML + 0.30*rule when evidence exists.

## Primary validation results

| Candidate | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | TP | TN | FP | FN | ML-positive malicious retained | ML FPs suppressed | New FP | New FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CONDITIONAL_RULE_ADJUSTMENT | 0.7536 | 0.5591 | 0.6420 | 0.6755 | 0.9595 | 0.000732 | 0.4409 | 52 | 23210 | 17 | 41 | 52 | 29 | 0 | 10 |
| CONFIGURED_WEIGHT_NO_RENORMALIZATION | 1.0000 | 0.0108 | 0.0213 | 0.6169 | 0.9098 | 0.000000 | 0.9892 | 1 | 23227 | 0 | 92 | 1 | 46 | 0 | 61 |
| CURRENT | 0.9474 | 0.3871 | 0.5496 | 0.6169 | 0.9098 | 0.000086 | 0.6129 | 36 | 23225 | 2 | 57 | 36 | 44 | 0 | 26 |
| EVIDENCE_AWARE | 0.8966 | 0.5591 | 0.6887 | 0.7042 | 0.9369 | 0.000258 | 0.4409 | 52 | 23221 | 6 | 41 | 52 | 40 | 0 | 10 |
| ML_DOMINANT_NO_RULE | 0.8000 | 0.5591 | 0.6582 | 0.6996 | 0.9593 | 0.000560 | 0.4409 | 52 | 23214 | 13 | 41 | 52 | 33 | 0 | 10 |
| ML_ONLY_REFERENCE (threshold 20) | 0.5741 | 0.6667 | 0.6169 | 0.6833 | 0.9787 | 0.001980 | 0.3333 | 62 | 23181 | 46 | 31 | — | — | — | — |

## Score distributions

| Candidate | Min | Q25 | Median | Mean | Q75 | Max | Rule evidence rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| CONDITIONAL_RULE_ADJUSTMENT | 0.001 | 1.819 | 1.958 | 2.484 | 2.421 | 93.432 | 0.687 |
| CONFIGURED_WEIGHT_NO_RENORMALIZATION | 0.000 | 0.912 | 2.193 | 1.872 | 2.289 | 37.220 | 0.687 |
| CURRENT | 0.001 | 1.520 | 3.655 | 3.120 | 3.814 | 62.033 | 0.687 |
| EVIDENCE_AWARE | 0.001 | 3.039 | 3.665 | 3.500 | 3.849 | 86.324 | 0.687 |
| ML_DOMINANT_NO_RULE | 0.001 | 2.173 | 2.265 | 2.593 | 2.584 | 86.324 | 0.687 |

## Threshold sensitivity

### CONDITIONAL_RULE_ADJUSTMENT

| Threshold | F1 | Recall | FPR | FNR | TP | TN | FP | FN |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.3061 | 0.8065 | 0.013863 | 0.1935 | 75 | 22905 | 322 | 18 |
| 20 | 0.6146 | 0.6774 | 0.002110 | 0.3226 | 63 | 23178 | 49 | 30 |
| 25 | 0.6322 | 0.5914 | 0.001119 | 0.4086 | 55 | 23201 | 26 | 38 |
| 30 | 0.6420 | 0.5591 | 0.000732 | 0.4409 | 52 | 23210 | 17 | 41 |
| 35 | 0.6065 | 0.5054 | 0.000646 | 0.4946 | 47 | 23212 | 15 | 46 |
| 40 | 0.5946 | 0.4731 | 0.000474 | 0.5269 | 44 | 23216 | 11 | 49 |
| 50 | 0.5821 | 0.4194 | 0.000086 | 0.5806 | 39 | 23225 | 2 | 54 |
| 60 | 0.5354 | 0.3656 | 0.000000 | 0.6344 | 34 | 23227 | 0 | 59 |
| 70 | 0.4628 | 0.3011 | 0.000000 | 0.6989 | 28 | 23227 | 0 | 65 |

### CONFIGURED_WEIGHT_NO_RENORMALIZATION

| Threshold | F1 | Recall | FPR | FNR | TP | TN | FP | FN |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.5939 | 0.5269 | 0.000990 | 0.4731 | 49 | 23204 | 23 | 44 |
| 20 | 0.4878 | 0.3226 | 0.000000 | 0.6774 | 30 | 23227 | 0 | 63 |
| 25 | 0.2453 | 0.1398 | 0.000000 | 0.8602 | 13 | 23227 | 0 | 80 |
| 30 | 0.0213 | 0.0108 | 0.000000 | 0.9892 | 1 | 23227 | 0 | 92 |
| 35 | 0.0213 | 0.0108 | 0.000000 | 0.9892 | 1 | 23227 | 0 | 92 |
| 40 | 0.0000 | 0.0000 | 0.000000 | 1.0000 | 0 | 23227 | 0 | 93 |
| 50 | 0.0000 | 0.0000 | 0.000000 | 1.0000 | 0 | 23227 | 0 | 93 |
| 60 | 0.0000 | 0.0000 | 0.000000 | 1.0000 | 0 | 23227 | 0 | 93 |
| 70 | 0.0000 | 0.0000 | 0.000000 | 1.0000 | 0 | 23227 | 0 | 93 |

### CURRENT

| Threshold | F1 | Recall | FPR | FNR | TP | TN | FP | FN |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.4758 | 0.6882 | 0.004822 | 0.3118 | 64 | 23115 | 112 | 29 |
| 20 | 0.5732 | 0.4839 | 0.000818 | 0.5161 | 45 | 23208 | 19 | 48 |
| 25 | 0.5634 | 0.4301 | 0.000387 | 0.5699 | 40 | 23218 | 9 | 53 |
| 30 | 0.5496 | 0.3871 | 0.000086 | 0.6129 | 36 | 23225 | 2 | 57 |
| 35 | 0.4754 | 0.3118 | 0.000000 | 0.6882 | 29 | 23227 | 0 | 64 |
| 40 | 0.4103 | 0.2581 | 0.000000 | 0.7419 | 24 | 23227 | 0 | 69 |
| 50 | 0.0213 | 0.0108 | 0.000000 | 0.9892 | 1 | 23227 | 0 | 92 |
| 60 | 0.0213 | 0.0108 | 0.000000 | 0.9892 | 1 | 23227 | 0 | 92 |
| 70 | 0.0000 | 0.0000 | 0.000000 | 1.0000 | 0 | 23227 | 0 | 93 |

### EVIDENCE_AWARE

| Threshold | F1 | Recall | FPR | FNR | TP | TN | FP | FN |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.3411 | 0.7849 | 0.011280 | 0.2151 | 73 | 22965 | 262 | 20 |
| 20 | 0.6492 | 0.6667 | 0.001550 | 0.3333 | 62 | 23191 | 36 | 31 |
| 25 | 0.6708 | 0.5806 | 0.000603 | 0.4194 | 54 | 23213 | 14 | 39 |
| 30 | 0.6887 | 0.5591 | 0.000258 | 0.4409 | 52 | 23221 | 6 | 41 |
| 35 | 0.6286 | 0.4731 | 0.000129 | 0.5269 | 44 | 23224 | 3 | 49 |
| 40 | 0.5882 | 0.4301 | 0.000129 | 0.5699 | 40 | 23224 | 3 | 53 |
| 50 | 0.5354 | 0.3656 | 0.000000 | 0.6344 | 34 | 23227 | 0 | 59 |
| 60 | 0.4878 | 0.3226 | 0.000000 | 0.6774 | 30 | 23227 | 0 | 63 |
| 70 | 0.4237 | 0.2688 | 0.000000 | 0.7312 | 25 | 23227 | 0 | 68 |

### ML_DOMINANT_NO_RULE

| Threshold | F1 | Recall | FPR | FNR | TP | TN | FP | FN |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.3476 | 0.7849 | 0.010936 | 0.2151 | 73 | 22973 | 254 | 20 |
| 20 | 0.6392 | 0.6667 | 0.001679 | 0.3333 | 62 | 23188 | 39 | 31 |
| 25 | 0.6585 | 0.5806 | 0.000732 | 0.4194 | 54 | 23210 | 17 | 39 |
| 30 | 0.6582 | 0.5591 | 0.000560 | 0.4409 | 52 | 23214 | 13 | 41 |
| 35 | 0.6389 | 0.4946 | 0.000215 | 0.5054 | 46 | 23222 | 5 | 47 |
| 40 | 0.6187 | 0.4624 | 0.000129 | 0.5376 | 43 | 23224 | 3 | 50 |
| 50 | 0.5581 | 0.3871 | 0.000000 | 0.6129 | 36 | 23227 | 0 | 57 |
| 60 | 0.4878 | 0.3226 | 0.000000 | 0.6774 | 30 | 23227 | 0 | 63 |
| 70 | 0.4370 | 0.2796 | 0.000000 | 0.7204 | 26 | 23227 | 0 | 67 |

### ML_ONLY_REFERENCE

| Threshold | F1 | Recall | FPR | FNR | TP | TN | FP | FN |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.3394 | 0.7957 | 0.011581 | 0.2043 | 74 | 22958 | 269 | 19 |
| 20 | 0.6169 | 0.6667 | 0.001980 | 0.3333 | 62 | 23181 | 46 | 31 |
| 25 | 0.6429 | 0.5806 | 0.000904 | 0.4194 | 54 | 23206 | 21 | 39 |
| 30 | 0.6460 | 0.5591 | 0.000689 | 0.4409 | 52 | 23211 | 16 | 41 |
| 35 | 0.6013 | 0.4946 | 0.000603 | 0.5054 | 46 | 23213 | 14 | 47 |
| 40 | 0.6099 | 0.4624 | 0.000215 | 0.5376 | 43 | 23222 | 5 | 50 |
| 50 | 0.5909 | 0.4194 | 0.000000 | 0.5806 | 39 | 23227 | 0 | 54 |
| 60 | 0.5238 | 0.3548 | 0.000000 | 0.6452 | 33 | 23227 | 0 | 60 |
| 70 | 0.4500 | 0.2903 | 0.000000 | 0.7097 | 27 | 23227 | 0 | 66 |

## Validation recommendation

**Recommended candidate for a later TEST-only confirmation: EVIDENCE_AWARE.** On validation it had the highest F1 among the proposed fusion candidates (`0.6887`), highest recall among the candidates (`0.5591`), and precision `0.8966`. It retained 52 of the 62 validation malicious URLs detected by ML-only, suppressed 40 of 46 ML-only false positives, introduced 0 new false positives relative to the ML reference, and introduced 10 new false negatives.

This is not a claim that it is better on TEST. The next step, if approved, is one locked, one-time evaluation on the untouched TEST partition using the selected candidate and its pre-declared threshold.

CONFIGURED_WEIGHT_NO_RENORMALIZATION is rejected for follow-up because the fixed zero contribution from unavailable signals compresses scores and produced recall `0.0108` at threshold 30. ML_DOMINANT_NO_RULE and CONDITIONAL_RULE_ADJUSTMENT preserve more of the ML signal but had lower validation F1 than EVIDENCE_AWARE at threshold 30.
