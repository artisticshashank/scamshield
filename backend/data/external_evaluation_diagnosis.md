# External Evaluation Diagnosis

## Scope and locked state

Strict views were created in memory by excluding every record whose normalized URL occurs anywhere in `Dataset.csv`, including frozen training, validation, and test partitions. Original sources, production code, model artifact, thresholds, and fusion weights were unchanged. No retraining, refitting, tuning, threshold search, or network calls occurred.

- Dataset.csv SHA-256: `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1`
- Artifact SHA-256: `fda0c7b574ab944e58af3446d8bd806c4e0ae4516c8610373588df454acd7885`
- Thresholds: ML 20, suspicious 30, dangerous 70
- Split: `{'seed': 42, 'strategy': 'domain_grouped', 'test': 23319, 'train': 69960, 'validation': 23320}`

## Strict-clean counts and leakage impact

### PhishVN v3.1.0 Open

- Original records: 8941
- Strict-clean records: 8931
- Excluded normalized-overlap records: 10
- Excluded label counts: `{'0': 10}`
- Original label counts: `{'0': 3845, '1': 5096}`
- Strict label counts: `{'0': 3835, '1': 5096}`
- Internal exact duplicates retained: 0
- Internal normalized duplicates retained: 2

### PhishBench-External D4v v2

- Original records: 1000
- Strict-clean records: 995
- Excluded normalized-overlap records: 5
- Excluded label counts: `{'0': 5}`
- Original label counts: `{'0': 500, '1': 500}`
- Strict label counts: `{'0': 495, '1': 500}`
- Internal exact duplicates retained: 2
- Internal normalized duplicates retained: 6

## Label verification

- PhishVN: `label=phishing` maps to positive class 1; `label=benign` maps to class 0.
- PhishBench: `Results=1` maps to phishing class 1; `Results=0` maps to benign class 0.
- No label inversion or relabeling was performed.

## Metrics: original versus strict-clean

### PhishVN v3.1.0 Open

#### Original

| Configuration | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | TP | TN | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ML_ONLY | 58.2821% | 71.7932% | 44.1523% | 54.6780% | 66.9901% | 50.9380% | 22.9909% | 55.8477% | 2250 | 2961 | 884 | 2846 |
| RULE_PLUS_ML | 54.0208% | 78.3535% | 26.7072% | 39.8361% | 66.9599% | 51.0112% | 9.7789% | 73.2928% | 1361 | 3469 | 376 | 3735 |
| FULL_SCAMSHIELD | 54.0208% | 78.3535% | 26.7072% | 39.8361% | 66.9599% | 51.0112% | 9.7789% | 73.2928% | 1361 | 3469 | 376 | 3735 |


#### Strict-clean

| Configuration | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | TP | TN | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ML_ONLY | 58.2354% | 71.7932% | 44.1523% | 54.6780% | 67.0091% | 50.8767% | 23.0508% | 55.8477% | 2250 | 2951 | 884 | 2846 |
| RULE_PLUS_ML | 53.9693% | 78.3535% | 26.7072% | 39.8361% | 66.9788% | 50.9498% | 9.8044% | 73.2928% | 1361 | 3459 | 376 | 3735 |
| FULL_SCAMSHIELD | 53.9693% | 78.3535% | 26.7072% | 39.8361% | 66.9788% | 50.9498% | 9.8044% | 73.2928% | 1361 | 3459 | 376 | 3735 |


### PhishBench-External D4v v2

#### Original

| Configuration | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | TP | TN | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ML_ONLY | 71.6000% | 65.0000% | 93.6000% | 76.7213% | 88.9362% | 88.1188% | 50.4000% | 6.4000% | 468 | 248 | 252 | 32 |
| RULE_PLUS_ML | 77.3000% | 74.6835% | 82.6000% | 78.4425% | 87.6866% | 86.2264% | 28.0000% | 17.4000% | 413 | 360 | 140 | 87 |
| FULL_SCAMSHIELD | 77.3000% | 74.6835% | 82.6000% | 78.4425% | 87.6866% | 86.2264% | 28.0000% | 17.4000% | 413 | 360 | 140 | 87 |


#### Strict-clean

| Configuration | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | TP | TN | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ML_ONLY | 71.4573% | 65.0000% | 93.6000% | 76.7213% | 88.9437% | 88.0242% | 50.9091% | 6.4000% | 468 | 243 | 252 | 32 |
| RULE_PLUS_ML | 77.1859% | 74.6835% | 82.6000% | 78.4425% | 87.6954% | 86.1147% | 28.2828% | 17.4000% | 413 | 355 | 140 | 87 |
| FULL_SCAMSHIELD | 77.1859% | 74.6835% | 82.6000% | 78.4425% | 87.6954% | 86.1147% | 28.2828% | 17.4000% | 413 | 355 | 140 | 87 |


## Original Dataset.csv TEST reference

| Configuration | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR | TP | TN | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ML_ONLY | 99.3739% | 82.8390% | 85.7456% | 84.2672% | 91.9341% | 99.3122% | 0.3543% | 14.2544% | 391 | 22782 | 81 | 65 |
| RULE_PLUS_ML | 99.3739% | 82.8390% | 85.7456% | 84.2672% | 91.9341% | 99.3122% | 0.3543% | 14.2544% | 391 | 22782 | 81 | 65 |
| FULL_SCAMSHIELD | 99.3739% | 82.8390% | 85.7456% | 84.2672% | 91.9341% | 99.3122% | 0.3543% | 14.2544% | 391 | 22782 | 81 | 65 |

## Distribution comparison

The JSON report contains full numeric distributions for URL length, UTF-8 byte length, HTTPS, IP hosts, punycode, hostname/subdomain/path/query statistics, suspicious TLDs, class balance, decision scores by class, score quantiles, and predicted-positive rates. The original Dataset.csv TEST distribution is included as the comparison reference.

### PhishVN v3.1.0 Open

#### URL and feature distributions

```json
{
  "original": {
    "binary": {
      "https": {
        "count": 8941,
        "proportion": 0.9986578682473997,
        "true": 8929
      },
      "ip_host": {
        "count": 8941,
        "proportion": 0.0,
        "true": 0
      },
      "punycode": {
        "count": 8941,
        "proportion": 0.0011184431271669835,
        "true": 10
      },
      "suspicious_tld": {
        "count": 8941,
        "proportion": 0.009954143831786154,
        "true": 89
      }
    },
    "class_balance": {},
    "domain_length_stats": {
      "count": 8941,
      "max": 72.0,
      "median": 17.0,
      "min": 4.0,
      "p05": 9.0,
      "p25": 13.0,
      "p75": 23.0,
      "p95": 33.0
    },
    "domain_unique": 8920,
    "feature_parse_success": 8941,
    "numeric": {
      "byte_length": {
        "count": 8941,
        "max": 186.0,
        "median": 26.0,
        "min": 13.0,
        "p05": 18.0,
        "p25": 22.0,
        "p75": 32.0,
        "p95": 42.0
      },
      "dot_count": {
        "count": 8941,
        "max": 5.0,
        "median": 2.0,
        "min": 1.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 3.0,
        "p95": 4.0
      },
      "hostname_length": {
        "count": 8941,
        "max": 72.0,
        "median": 17.0,
        "min": 4.0,
        "p05": 9.0,
        "p25": 13.0,
        "p75": 23.0,
        "p95": 33.0
      },
      "path_depth": {
        "count": 8941,
        "max": 5.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "path_length": {
        "count": 8941,
        "max": 52.0,
        "median": 1.0,
        "min": 1.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 1.0,
        "p95": 1.0
      },
      "query_length": {
        "count": 8941,
        "max": 113.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "query_parameter_count": {
        "count": 8941,
        "max": 3.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "subdomain_count": {
        "count": 8941,
        "max": 4.0,
        "median": 1.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 2.0,
        "p95": 3.0
      },
      "url_length": {
        "count": 8941,
        "max": 186.0,
        "median": 26.0,
        "min": 13.0,
        "p05": 18.0,
        "p25": 22.0,
        "p75": 32.0,
        "p95": 42.0
      }
    },
    "records": 8941,
    "registered_domain_unique": 3962
  },
  "strict": {
    "binary": {
      "https": {
        "count": 8931,
        "proportion": 0.9986563654685925,
        "true": 8919
      },
      "ip_host": {
        "count": 8931,
        "proportion": 0.0,
        "true": 0
      },
      "punycode": {
        "count": 8931,
        "proportion": 0.0011196954428395476,
        "true": 10
      },
      "suspicious_tld": {
        "count": 8931,
        "proportion": 0.009965289441271974,
        "true": 89
      }
    },
    "class_balance": {},
    "domain_length_stats": {
      "count": 8931,
      "max": 72.0,
      "median": 17.0,
      "min": 4.0,
      "p05": 9.0,
      "p25": 13.0,
      "p75": 23.0,
      "p95": 33.0
    },
    "domain_unique": 8910,
    "feature_parse_success": 8931,
    "numeric": {
      "byte_length": {
        "count": 8931,
        "max": 186.0,
        "median": 26.0,
        "min": 13.0,
        "p05": 18.0,
        "p25": 22.0,
        "p75": 32.0,
        "p95": 42.0
      },
      "dot_count": {
        "count": 8931,
        "max": 5.0,
        "median": 2.0,
        "min": 1.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 3.0,
        "p95": 4.0
      },
      "hostname_length": {
        "count": 8931,
        "max": 72.0,
        "median": 17.0,
        "min": 4.0,
        "p05": 9.0,
        "p25": 13.0,
        "p75": 23.0,
        "p95": 33.0
      },
      "path_depth": {
        "count": 8931,
        "max": 5.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "path_length": {
        "count": 8931,
        "max": 52.0,
        "median": 1.0,
        "min": 1.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 1.0,
        "p95": 1.0
      },
      "query_length": {
        "count": 8931,
        "max": 113.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "query_parameter_count": {
        "count": 8931,
        "max": 3.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "subdomain_count": {
        "count": 8931,
        "max": 4.0,
        "median": 1.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 2.0,
        "p95": 3.0
      },
      "url_length": {
        "count": 8931,
        "max": 186.0,
        "median": 26.0,
        "min": 13.0,
        "p05": 18.0,
        "p25": 22.0,
        "p75": 32.0,
        "p95": 42.0
      }
    },
    "records": 8931,
    "registered_domain_unique": 3956
  },
  "dataset_test": {
    "binary": {
      "https": {
        "count": 23319,
        "proportion": 0.34748488357133667,
        "true": 8103
      },
      "ip_host": {
        "count": 23319,
        "proportion": 0.0,
        "true": 0
      },
      "punycode": {
        "count": 23319,
        "proportion": 0.003602212787855397,
        "true": 84
      },
      "suspicious_tld": {
        "count": 23319,
        "proportion": 8.576697113941421e-05,
        "true": 2
      }
    },
    "by_class": {
      "benign": {
        "binary": {
          "https": {
            "count": 22863,
            "proportion": 0.33569522809779995,
            "true": 7675
          },
          "ip_host": {
            "count": 22863,
            "proportion": 0.0,
            "true": 0
          },
          "punycode": {
            "count": 22863,
            "proportion": 0.0016620740935135371,
            "true": 38
          },
          "suspicious_tld": {
            "count": 22863,
            "proportion": 0.0,
            "true": 0
          }
        },
        "class_balance": {},
        "domain_length_stats": {
          "count": 22863,
          "max": 73.0,
          "median": 16.0,
          "min": 4.0,
          "p05": 11.0,
          "p25": 14.0,
          "p75": 20.0,
          "p95": 27.0
        },
        "domain_unique": 20886,
        "feature_parse_success": 22863,
        "numeric": {
          "byte_length": {
            "count": 22863,
            "max": 257.0,
            "median": 26.0,
            "min": 13.0,
            "p05": 20.0,
            "p25": 23.0,
            "p75": 32.0,
            "p95": 52.0
          },
          "dot_count": {
            "count": 22863,
            "max": 8.0,
            "median": 2.0,
            "min": 1.0,
            "p05": 2.0,
            "p25": 2.0,
            "p75": 3.0,
            "p95": 3.0
          },
          "hostname_length": {
            "count": 22863,
            "max": 73.0,
            "median": 16.0,
            "min": 4.0,
            "p05": 11.0,
            "p25": 14.0,
            "p75": 20.0,
            "p95": 27.0
          },
          "path_depth": {
            "count": 22863,
            "max": 11.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 1.0,
            "p95": 2.0
          },
          "path_length": {
            "count": 22863,
            "max": 178.0,
            "median": 1.0,
            "min": 1.0,
            "p05": 1.0,
            "p25": 1.0,
            "p75": 3.0,
            "p95": 24.0
          },
          "query_length": {
            "count": 22863,
            "max": 111.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p95": 0.0
          },
          "query_parameter_count": {
            "count": 22863,
            "max": 8.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p95": 0.0
          },
          "subdomain_count": {
            "count": 22863,
            "max": 7.0,
            "median": 1.0,
            "min": 0.0,
            "p05": 1.0,
            "p25": 1.0,
            "p75": 2.0,
            "p95": 2.0
          },
          "url_length": {
            "count": 22863,
            "max": 257.0,
            "median": 26.0,
            "min": 13.0,
            "p05": 20.0,
            "p25": 23.0,
            "p75": 32.0,
            "p95": 52.0
          }
        },
        "records": 22863,
        "registered_domain_unique": 15835
      },
      "phishing": {
        "binary": {
          "https": {
            "count": 456,
            "proportion": 0.9385964912280702,
            "true": 428
          },
          "ip_host": {
            "count": 456,
            "proportion": 0.0,
            "true": 0
          },
          "punycode": {
            "count": 456,
            "proportion": 0.10087719298245613,
            "true": 46
          },
          "suspicious_tld": {
            "count": 456,
            "proportion": 0.0043859649122807015,
            "true": 2
          }
        },
        "class_balance": {},
        "domain_length_stats": {
          "count": 456,
          "max": 67.0,
          "median": 21.0,
          "min": 6.0,
          "p05": 8.0,
          "p25": 16.0,
          "p75": 27.0,
          "p95": 51.0
        },
        "domain_unique": 397,
        "feature_parse_success": 456,
        "numeric": {
          "byte_length": {
            "count": 456,
            "max": 424.0,
            "median": 36.0,
            "min": 19.0,
            "p05": 25.0,
            "p25": 29.0,
            "p75": 50.0,
            "p95": 92.25
          },
          "dot_count": {
            "count": 456,
            "max": 5.0,
            "median": 2.0,
            "min": 1.0,
            "p05": 1.0,
            "p25": 2.0,
            "p75": 2.0,
            "p95": 3.0
          },
          "hostname_length": {
            "count": 456,
            "max": 67.0,
            "median": 21.0,
            "min": 6.0,
            "p05": 8.0,
            "p25": 16.0,
            "p75": 27.0,
            "p95": 51.0
          },
          "path_depth": {
            "count": 456,
            "max": 10.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 1.0,
            "p95": 4.25
          },
          "path_length": {
            "count": 456,
            "max": 178.0,
            "median": 1.0,
            "min": 1.0,
            "p05": 1.0,
            "p25": 1.0,
            "p75": 13.0,
            "p95": 38.0
          },
          "query_length": {
            "count": 456,
            "max": 379.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p95": 27.0
          },
          "query_parameter_count": {
            "count": 456,
            "max": 9.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p95": 1.0
          },
          "subdomain_count": {
            "count": 456,
            "max": 4.0,
            "median": 1.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 1.0,
            "p75": 1.0,
            "p95": 2.0
          },
          "url_length": {
            "count": 456,
            "max": 424.0,
            "median": 36.0,
            "min": 19.0,
            "p05": 25.0,
            "p25": 29.0,
            "p75": 50.0,
            "p95": 92.25
          }
        },
        "records": 456,
        "registered_domain_unique": 225
      }
    },
    "class_balance": {},
    "domain_length_stats": {
      "count": 23319,
      "max": 73.0,
      "median": 16.0,
      "min": 4.0,
      "p05": 11.0,
      "p25": 14.0,
      "p75": 20.0,
      "p95": 27.0
    },
    "domain_unique": 21283,
    "feature_parse_success": 23319,
    "numeric": {
      "byte_length": {
        "count": 23319,
        "max": 424.0,
        "median": 26.0,
        "min": 13.0,
        "p05": 20.0,
        "p25": 23.0,
        "p75": 33.0,
        "p95": 53.0
      },
      "dot_count": {
        "count": 23319,
        "max": 8.0,
        "median": 2.0,
        "min": 1.0,
        "p05": 2.0,
        "p25": 2.0,
        "p75": 3.0,
        "p95": 3.0
      },
      "hostname_length": {
        "count": 23319,
        "max": 73.0,
        "median": 16.0,
        "min": 4.0,
        "p05": 11.0,
        "p25": 14.0,
        "p75": 20.0,
        "p95": 27.0
      },
      "path_depth": {
        "count": 23319,
        "max": 11.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 1.0,
        "p95": 2.0
      },
      "path_length": {
        "count": 23319,
        "max": 178.0,
        "median": 1.0,
        "min": 1.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 3.0,
        "p95": 25.0
      },
      "query_length": {
        "count": 23319,
        "max": 379.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "query_parameter_count": {
        "count": 23319,
        "max": 9.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "subdomain_count": {
        "count": 23319,
        "max": 7.0,
        "median": 1.0,
        "min": 0.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 2.0,
        "p95": 2.0
      },
      "url_length": {
        "count": 23319,
        "max": 424.0,
        "median": 26.0,
        "min": 13.0,
        "p05": 20.0,
        "p25": 23.0,
        "p75": 33.0,
        "p95": 53.0
      }
    },
    "records": 23319,
    "registered_domain_unique": 16052
  }
}
```

#### Decision-score distributions by class

```json
{
  "original": {
    "fusion_all": {
      "count": 8941,
      "max": 97.65413929358469,
      "median": 14.201487117173766,
      "min": 0.0036048554789694393,
      "p05": 1.2309853350063076,
      "p25": 7.354631602308297,
      "p75": 26.098767934040843,
      "p95": 52.379366923157136
    },
    "fusion_by_class": {
      "benign": {
        "count": 3845,
        "max": 91.90412399298583,
        "median": 13.418189940657147,
        "min": 0.0609254931452901,
        "p05": 5.456701118831,
        "p25": 9.556832207184653,
        "p75": 18.97117891945435,
        "p95": 38.13540506267938
      },
      "phishing": {
        "count": 5096,
        "max": 97.65413929358469,
        "median": 16.532577709117565,
        "min": 0.0036048554789694393,
        "p05": 0.871089074911833,
        "p25": 3.7495283292253547,
        "p75": 31.218113678046056,
        "p95": 60.465409647740195
      }
    },
    "ml_all": {
      "count": 8941,
      "max": 97.65413929358469,
      "median": 14.188338206713746,
      "min": 0.0036048554789694393,
      "p05": 1.2298720526686129,
      "p25": 7.288616755931519,
      "p75": 26.21330821715379,
      "p95": 54.18128343153108
    },
    "ml_by_class": {
      "benign": {
        "count": 3845,
        "max": 91.90412399298583,
        "median": 13.415480184133083,
        "min": 0.0609254931452901,
        "p05": 5.4172481592836945,
        "p25": 9.542797558052127,
        "p75": 18.97117891945435,
        "p95": 38.13540506267938
      },
      "phishing": {
        "count": 5096,
        "max": 97.65413929358469,
        "median": 16.50183898617884,
        "min": 0.0036048554789694393,
        "p05": 0.8668594074329059,
        "p25": 3.6949970610093557,
        "p75": 31.683727362064324,
        "p95": 62.653936993737624
      }
    }
  },
  "strict": {
    "fusion_all": {
      "count": 8931,
      "max": 97.65413929358469,
      "median": 14.208915881074805,
      "min": 0.0036048554789694393,
      "p05": 1.2320800180088067,
      "p25": 7.373722402094152,
      "p75": 26.10903986938054,
      "p95": 52.37989544553335
    },
    "fusion_by_class": {
      "benign": {
        "count": 3835,
        "max": 91.90412399298583,
        "median": 13.42198365181396,
        "min": 0.0609254931452901,
        "p05": 5.5638052301189775,
        "p25": 9.571925406369264,
        "p75": 18.979353752980572,
        "p95": 38.17039108517627
      },
      "phishing": {
        "count": 5096,
        "max": 97.65413929358469,
        "median": 16.532577709117565,
        "min": 0.0036048554789694393,
        "p05": 0.871089074911833,
        "p25": 3.7495283292253547,
        "p75": 31.218113678046056,
        "p95": 60.465409647740195
      }
    },
    "ml_all": {
      "count": 8931,
      "max": 97.65413929358469,
      "median": 14.193005415587026,
      "min": 0.0036048554789694393,
      "p05": 1.23096199193109,
      "p25": 7.295753093143638,
      "p75": 26.229861877391638,
      "p95": 54.18630638450857
    },
    "ml_by_class": {
      "benign": {
        "count": 3835,
        "max": 91.90412399298583,
        "median": 13.418744644701203,
        "min": 0.0609254931452901,
        "p05": 5.4654482602665695,
        "p25": 9.566184569189943,
        "p75": 18.979353752980572,
        "p95": 38.17039108517627
      },
      "phishing": {
        "count": 5096,
        "max": 97.65413929358469,
        "median": 16.50183898617884,
        "min": 0.0036048554789694393,
        "p05": 0.8668594074329059,
        "p25": 3.6949970610093557,
        "p75": 31.683727362064324,
        "p95": 62.653936993737624
      }
    }
  }
}
```

### PhishBench-External D4v v2

#### URL and feature distributions

```json
{
  "original": {
    "binary": {
      "https": {
        "count": 1000,
        "proportion": 0.923,
        "true": 923
      },
      "ip_host": {
        "count": 1000,
        "proportion": 0.002,
        "true": 2
      },
      "punycode": {
        "count": 1000,
        "proportion": 0.002,
        "true": 2
      },
      "suspicious_tld": {
        "count": 1000,
        "proportion": 0.004,
        "true": 4
      }
    },
    "class_balance": {},
    "domain_length_stats": {
      "count": 1000,
      "max": 69.0,
      "median": 12.0,
      "min": 4.0,
      "p05": 6.950000000000003,
      "p25": 10.0,
      "p75": 19.0,
      "p95": 36.049999999999955
    },
    "domain_unique": 901,
    "feature_parse_success": 1000,
    "numeric": {
      "byte_length": {
        "count": 1000,
        "max": 80.0,
        "median": 24.0,
        "min": 13.0,
        "p05": 16.0,
        "p25": 20.0,
        "p75": 35.0,
        "p95": 64.0
      },
      "dot_count": {
        "count": 1000,
        "max": 5.0,
        "median": 1.0,
        "min": 0.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 2.0,
        "p95": 2.0
      },
      "hostname_length": {
        "count": 1000,
        "max": 69.0,
        "median": 12.0,
        "min": 4.0,
        "p05": 6.950000000000003,
        "p25": 10.0,
        "p75": 19.0,
        "p95": 36.049999999999955
      },
      "path_depth": {
        "count": 1000,
        "max": 6.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 1.0,
        "p95": 3.0
      },
      "path_length": {
        "count": 1000,
        "max": 55.0,
        "median": 1.0,
        "min": 1.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 7.0,
        "p95": 20.0
      },
      "query_length": {
        "count": 1000,
        "max": 33.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "query_parameter_count": {
        "count": 1000,
        "max": 2.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "subdomain_count": {
        "count": 1000,
        "max": 4.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 1.0,
        "p95": 1.0
      },
      "url_length": {
        "count": 1000,
        "max": 80.0,
        "median": 24.0,
        "min": 13.0,
        "p05": 16.0,
        "p25": 20.0,
        "p75": 35.0,
        "p95": 64.0
      }
    },
    "records": 1000,
    "registered_domain_unique": 762
  },
  "strict": {
    "binary": {
      "https": {
        "count": 995,
        "proportion": 0.9226130653266331,
        "true": 918
      },
      "ip_host": {
        "count": 995,
        "proportion": 0.0020100502512562816,
        "true": 2
      },
      "punycode": {
        "count": 995,
        "proportion": 0.0020100502512562816,
        "true": 2
      },
      "suspicious_tld": {
        "count": 995,
        "proportion": 0.004020100502512563,
        "true": 4
      }
    },
    "class_balance": {},
    "domain_length_stats": {
      "count": 995,
      "max": 69.0,
      "median": 12.0,
      "min": 4.0,
      "p05": 7.0,
      "p25": 10.0,
      "p75": 19.0,
      "p95": 36.299999999999955
    },
    "domain_unique": 896,
    "feature_parse_success": 995,
    "numeric": {
      "byte_length": {
        "count": 995,
        "max": 80.0,
        "median": 24.0,
        "min": 13.0,
        "p05": 16.0,
        "p25": 20.0,
        "p75": 35.0,
        "p95": 64.0
      },
      "dot_count": {
        "count": 995,
        "max": 5.0,
        "median": 1.0,
        "min": 0.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 2.0,
        "p95": 2.0
      },
      "hostname_length": {
        "count": 995,
        "max": 69.0,
        "median": 12.0,
        "min": 4.0,
        "p05": 7.0,
        "p25": 10.0,
        "p75": 19.0,
        "p95": 36.299999999999955
      },
      "path_depth": {
        "count": 995,
        "max": 6.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 1.0,
        "p95": 3.0
      },
      "path_length": {
        "count": 995,
        "max": 55.0,
        "median": 1.0,
        "min": 1.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 7.0,
        "p95": 20.0
      },
      "query_length": {
        "count": 995,
        "max": 33.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "query_parameter_count": {
        "count": 995,
        "max": 2.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "subdomain_count": {
        "count": 995,
        "max": 4.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 1.0,
        "p95": 1.0
      },
      "url_length": {
        "count": 995,
        "max": 80.0,
        "median": 24.0,
        "min": 13.0,
        "p05": 16.0,
        "p25": 20.0,
        "p75": 35.0,
        "p95": 64.0
      }
    },
    "records": 995,
    "registered_domain_unique": 757
  },
  "dataset_test": {
    "binary": {
      "https": {
        "count": 23319,
        "proportion": 0.34748488357133667,
        "true": 8103
      },
      "ip_host": {
        "count": 23319,
        "proportion": 0.0,
        "true": 0
      },
      "punycode": {
        "count": 23319,
        "proportion": 0.003602212787855397,
        "true": 84
      },
      "suspicious_tld": {
        "count": 23319,
        "proportion": 8.576697113941421e-05,
        "true": 2
      }
    },
    "by_class": {
      "benign": {
        "binary": {
          "https": {
            "count": 22863,
            "proportion": 0.33569522809779995,
            "true": 7675
          },
          "ip_host": {
            "count": 22863,
            "proportion": 0.0,
            "true": 0
          },
          "punycode": {
            "count": 22863,
            "proportion": 0.0016620740935135371,
            "true": 38
          },
          "suspicious_tld": {
            "count": 22863,
            "proportion": 0.0,
            "true": 0
          }
        },
        "class_balance": {},
        "domain_length_stats": {
          "count": 22863,
          "max": 73.0,
          "median": 16.0,
          "min": 4.0,
          "p05": 11.0,
          "p25": 14.0,
          "p75": 20.0,
          "p95": 27.0
        },
        "domain_unique": 20886,
        "feature_parse_success": 22863,
        "numeric": {
          "byte_length": {
            "count": 22863,
            "max": 257.0,
            "median": 26.0,
            "min": 13.0,
            "p05": 20.0,
            "p25": 23.0,
            "p75": 32.0,
            "p95": 52.0
          },
          "dot_count": {
            "count": 22863,
            "max": 8.0,
            "median": 2.0,
            "min": 1.0,
            "p05": 2.0,
            "p25": 2.0,
            "p75": 3.0,
            "p95": 3.0
          },
          "hostname_length": {
            "count": 22863,
            "max": 73.0,
            "median": 16.0,
            "min": 4.0,
            "p05": 11.0,
            "p25": 14.0,
            "p75": 20.0,
            "p95": 27.0
          },
          "path_depth": {
            "count": 22863,
            "max": 11.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 1.0,
            "p95": 2.0
          },
          "path_length": {
            "count": 22863,
            "max": 178.0,
            "median": 1.0,
            "min": 1.0,
            "p05": 1.0,
            "p25": 1.0,
            "p75": 3.0,
            "p95": 24.0
          },
          "query_length": {
            "count": 22863,
            "max": 111.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p95": 0.0
          },
          "query_parameter_count": {
            "count": 22863,
            "max": 8.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p95": 0.0
          },
          "subdomain_count": {
            "count": 22863,
            "max": 7.0,
            "median": 1.0,
            "min": 0.0,
            "p05": 1.0,
            "p25": 1.0,
            "p75": 2.0,
            "p95": 2.0
          },
          "url_length": {
            "count": 22863,
            "max": 257.0,
            "median": 26.0,
            "min": 13.0,
            "p05": 20.0,
            "p25": 23.0,
            "p75": 32.0,
            "p95": 52.0
          }
        },
        "records": 22863,
        "registered_domain_unique": 15835
      },
      "phishing": {
        "binary": {
          "https": {
            "count": 456,
            "proportion": 0.9385964912280702,
            "true": 428
          },
          "ip_host": {
            "count": 456,
            "proportion": 0.0,
            "true": 0
          },
          "punycode": {
            "count": 456,
            "proportion": 0.10087719298245613,
            "true": 46
          },
          "suspicious_tld": {
            "count": 456,
            "proportion": 0.0043859649122807015,
            "true": 2
          }
        },
        "class_balance": {},
        "domain_length_stats": {
          "count": 456,
          "max": 67.0,
          "median": 21.0,
          "min": 6.0,
          "p05": 8.0,
          "p25": 16.0,
          "p75": 27.0,
          "p95": 51.0
        },
        "domain_unique": 397,
        "feature_parse_success": 456,
        "numeric": {
          "byte_length": {
            "count": 456,
            "max": 424.0,
            "median": 36.0,
            "min": 19.0,
            "p05": 25.0,
            "p25": 29.0,
            "p75": 50.0,
            "p95": 92.25
          },
          "dot_count": {
            "count": 456,
            "max": 5.0,
            "median": 2.0,
            "min": 1.0,
            "p05": 1.0,
            "p25": 2.0,
            "p75": 2.0,
            "p95": 3.0
          },
          "hostname_length": {
            "count": 456,
            "max": 67.0,
            "median": 21.0,
            "min": 6.0,
            "p05": 8.0,
            "p25": 16.0,
            "p75": 27.0,
            "p95": 51.0
          },
          "path_depth": {
            "count": 456,
            "max": 10.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 1.0,
            "p95": 4.25
          },
          "path_length": {
            "count": 456,
            "max": 178.0,
            "median": 1.0,
            "min": 1.0,
            "p05": 1.0,
            "p25": 1.0,
            "p75": 13.0,
            "p95": 38.0
          },
          "query_length": {
            "count": 456,
            "max": 379.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p95": 27.0
          },
          "query_parameter_count": {
            "count": 456,
            "max": 9.0,
            "median": 0.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p95": 1.0
          },
          "subdomain_count": {
            "count": 456,
            "max": 4.0,
            "median": 1.0,
            "min": 0.0,
            "p05": 0.0,
            "p25": 1.0,
            "p75": 1.0,
            "p95": 2.0
          },
          "url_length": {
            "count": 456,
            "max": 424.0,
            "median": 36.0,
            "min": 19.0,
            "p05": 25.0,
            "p25": 29.0,
            "p75": 50.0,
            "p95": 92.25
          }
        },
        "records": 456,
        "registered_domain_unique": 225
      }
    },
    "class_balance": {},
    "domain_length_stats": {
      "count": 23319,
      "max": 73.0,
      "median": 16.0,
      "min": 4.0,
      "p05": 11.0,
      "p25": 14.0,
      "p75": 20.0,
      "p95": 27.0
    },
    "domain_unique": 21283,
    "feature_parse_success": 23319,
    "numeric": {
      "byte_length": {
        "count": 23319,
        "max": 424.0,
        "median": 26.0,
        "min": 13.0,
        "p05": 20.0,
        "p25": 23.0,
        "p75": 33.0,
        "p95": 53.0
      },
      "dot_count": {
        "count": 23319,
        "max": 8.0,
        "median": 2.0,
        "min": 1.0,
        "p05": 2.0,
        "p25": 2.0,
        "p75": 3.0,
        "p95": 3.0
      },
      "hostname_length": {
        "count": 23319,
        "max": 73.0,
        "median": 16.0,
        "min": 4.0,
        "p05": 11.0,
        "p25": 14.0,
        "p75": 20.0,
        "p95": 27.0
      },
      "path_depth": {
        "count": 23319,
        "max": 11.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 1.0,
        "p95": 2.0
      },
      "path_length": {
        "count": 23319,
        "max": 178.0,
        "median": 1.0,
        "min": 1.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 3.0,
        "p95": 25.0
      },
      "query_length": {
        "count": 23319,
        "max": 379.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "query_parameter_count": {
        "count": 23319,
        "max": 9.0,
        "median": 0.0,
        "min": 0.0,
        "p05": 0.0,
        "p25": 0.0,
        "p75": 0.0,
        "p95": 0.0
      },
      "subdomain_count": {
        "count": 23319,
        "max": 7.0,
        "median": 1.0,
        "min": 0.0,
        "p05": 1.0,
        "p25": 1.0,
        "p75": 2.0,
        "p95": 2.0
      },
      "url_length": {
        "count": 23319,
        "max": 424.0,
        "median": 26.0,
        "min": 13.0,
        "p05": 20.0,
        "p25": 23.0,
        "p75": 33.0,
        "p95": 53.0
      }
    },
    "records": 23319,
    "registered_domain_unique": 16052
  }
}
```

#### Decision-score distributions by class

```json
{
  "original": {
    "fusion_all": {
      "count": 1000,
      "max": 99.80731504723977,
      "median": 36.77723071879106,
      "min": 0.0014161240626238288,
      "p05": 5.000588281464083,
      "p25": 17.92773067317311,
      "p75": 64.49283868255017,
      "p95": 97.46211580352823
    },
    "fusion_by_class": {
      "benign": {
        "count": 500,
        "max": 99.06996136067116,
        "median": 20.11638014803578,
        "min": 0.0014161240626238288,
        "p05": 2.3806093365494703,
        "p25": 12.052759742747757,
        "p75": 32.46567192858323,
        "p95": 57.97524911256916
      },
      "phishing": {
        "count": 500,
        "max": 99.80731504723977,
        "median": 62.31647825697112,
        "min": 4.665222171967125,
        "p05": 14.3332013553925,
        "p25": 46.667030948564914,
        "p75": 88.3942464232696,
        "p95": 98.59844131866208
      }
    },
    "ml_all": {
      "count": 1000,
      "max": 99.80731504723977,
      "median": 38.01253567270476,
      "min": 0.0014161240626238288,
      "p05": 4.108511861153474,
      "p25": 18.292228284708486,
      "p75": 71.90850389960714,
      "p95": 98.16956337594108
    },
    "ml_by_class": {
      "benign": {
        "count": 500,
        "max": 99.06996136067116,
        "median": 20.11638014803578,
        "min": 0.0014161240626238288,
        "p05": 2.3806093365494703,
        "p25": 12.052759742747757,
        "p75": 32.55931915256346,
        "p95": 62.67939787471973
      },
      "phishing": {
        "count": 500,
        "max": 99.80731504723977,
        "median": 70.1705325185385,
        "min": 2.104792976789537,
        "p05": 15.2172524563318,
        "p25": 49.07800583492077,
        "p75": 93.89691573299386,
        "p95": 98.99030752853731
      }
    }
  },
  "strict": {
    "fusion_all": {
      "count": 995,
      "max": 99.80731504723977,
      "median": 36.93340346378871,
      "min": 0.0609254931452901,
      "p05": 5.210713784015596,
      "p25": 18.133108017460287,
      "p75": 64.53868842861597,
      "p95": 97.51591958746302
    },
    "fusion_by_class": {
      "benign": {
        "count": 495,
        "max": 99.06996136067116,
        "median": 20.27198076996107,
        "min": 0.0609254931452901,
        "p05": 2.530809780106135,
        "p25": 12.142368707880772,
        "p75": 32.61979176441522,
        "p95": 58.0395922922446
      },
      "phishing": {
        "count": 500,
        "max": 99.80731504723977,
        "median": 62.31647825697112,
        "min": 4.665222171967125,
        "p05": 14.3332013553925,
        "p25": 46.667030948564914,
        "p75": 88.3942464232696,
        "p95": 98.59844131866208
      }
    },
    "ml_all": {
      "count": 995,
      "max": 99.80731504723977,
      "median": 38.72339132539682,
      "min": 0.0609254931452901,
      "p05": 4.550601367337779,
      "p25": 18.390111613869962,
      "p75": 72.03294639864582,
      "p95": 98.17048073024877
    },
    "ml_by_class": {
      "benign": {
        "count": 495,
        "max": 99.06996136067116,
        "median": 20.27198076996107,
        "min": 0.0609254931452901,
        "p05": 2.530809780106135,
        "p25": 12.142368707880772,
        "p75": 32.816365007392356,
        "p95": 62.844235163287784
      },
      "phishing": {
        "count": 500,
        "max": 99.80731504723977,
        "median": 70.1705325185385,
        "min": 2.104792976789537,
        "p05": 15.2172524563318,
        "p25": 49.07800583492077,
        "p75": 93.89691573299386,
        "p95": 98.99030752853731
      }
    }
  }
}
```

## PhishVN diagnosis

The label mapping is consistent with the supplied schema and class counts; no inversion evidence was found. Strict filtering removes only the measured normalized overlaps with Dataset.csv, so leakage does not explain the overall ROC-AUC near 0.5. The measured class-conditional URL/byte, HTTPS, IP-host, punycode, domain, subdomain, path/query, TLD, and decision-score distributions support a substantial source/distribution shift and weak transfer of the frozen character model as a leading measurable association. They do not establish one exclusive causal mechanism. No preprocessing mismatch was introduced by the evaluator: the existing normalization, TF-IDF vectorizer, and artifact inference path were used unchanged.

## PhishBench diagnosis

The 1/0 label mapping is consistent with the documented balanced source. Strict filtering removes the measured Dataset.csv overlaps; strict metrics should be used for leakage-aware comparison. Its stronger score separation than PhishVN demonstrates source-dependent behavior, but does not establish superiority or production readiness.

## Limitations

- Strict filtering addresses normalized URL overlap with Dataset.csv only; internal duplicates and cross-source overlaps remain disclosed.
- Registered-domain counts are descriptive approximations.
- External reputation, DNS/RDAP/TLS, and redirect signals were not queried and remain unavailable rather than clean.
- Dataset.csv TEST is imbalanced, while PhishBench is balanced.
- Distribution association cannot by itself establish causation.
