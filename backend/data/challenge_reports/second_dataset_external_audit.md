# PhishBench-External D4v v2 External Audit

## Identity and provenance

- File: `Phishing Detection External Evaluation Dataset (1000 URLs).csv`
- SHA-256: `df25f4cae492c91cdca83887737a3d1672df71ebe8b581eeac21715a704b869f`
- Rows: 1000
- Source: Mendeley Data / PhishBench-External
- DOI: `10.17632/2ctjcnm9kn.2`
- Label mapping: `{'phishing': 1, 'malicious': 1, '1': 1, 'benign': 0, 'legitimate': 0, '0': 0}`

## Dataset quality

- Labels: `{'1': 500, '0': 500}`
- Accepted structural rows: 1000
- Invalid labels: 0
- Missing URLs: 0
- Malformed URLs: 0
- Exact duplicate rows: 2
- Normalized duplicate rows: 6
- Conflicting normalized URLs: 0
- Unique hosts: 901
- Unique registered-domain approximation: 762
- Date fields: `{'count': 0, 'unique': 0, 'min': None, 'max': None}`
- Source distribution: `{'<missing>': 1000}`
- Category distribution: `{'<missing>': 1000}`

## Leakage and overlap

- Exact overlap with Dataset.csv: 0
- Normalized overlap with Dataset.csv: 5
- Host overlap with Dataset.csv: 37
- Registered-domain overlap with Dataset.csv: 142
- Normalized overlap by frozen partition: `{'train': 5, 'validation': 0, 'test': 0}`
- Host overlap by frozen partition: `{'train': 0, 'validation': 0, 'test': 0}`
- Exact overlap with other external source: 0
- Normalized overlap with other external source: 41
- Host overlap with other external source: 41

The source is retained as an external benchmark with these overlaps disclosed; it is not described as completely leakage-free.
