# PhishVN v3.1.0 Open External Audit

## Identity and provenance

- File: `url_test.csv`
- SHA-256: `b692882e8ae26b2c0b217c090e92d3a19307a26acbfb3c8c89692db26d409bc9`
- Rows: 8941
- Source: PhishVN v3.1.0 Open
- DOI: `10.17632/b97hxbxtpd.4`
- Label mapping: `{'phishing': 1, 'malicious': 1, '1': 1, 'benign': 0, 'legitimate': 0, '0': 0}`

## Dataset quality

- Labels: `{'phishing': 5096, 'benign': 3845}`
- Accepted structural rows: 8941
- Invalid labels: 0
- Missing URLs: 0
- Malformed URLs: 0
- Exact duplicate rows: 0
- Normalized duplicate rows: 2
- Conflicting normalized URLs: 0
- Unique hosts: 8920
- Unique registered-domain approximation: 3962
- Date fields: `{'count': 8941, 'unique': 577, 'min': '01/03/2024', 'max': '31/10/2024'}`
- Source distribution: `{'tinnhiemmang': 487, 'tinnhiem_web': 2246, 'tinnhiem_org': 358, 'tranco': 888, 'tranco_vn': 353, 'openphish': 30, 'chongluadao': 4579}`
- Category distribution: `{'ecommerce': 491, 'telecom': 12, 'gov': 2495, 'other': 5616, 'gaming': 22, 'social': 46, 'delivery': 31, 'bank': 222, 'tax': 6}`

## Leakage and overlap

- Exact overlap with Dataset.csv: 0
- Normalized overlap with Dataset.csv: 10
- Host overlap with Dataset.csv: 14
- Registered-domain overlap with Dataset.csv: 104
- Normalized overlap by frozen partition: `{'train': 10, 'validation': 0, 'test': 0}`
- Host overlap by frozen partition: `{'train': 0, 'validation': 0, 'test': 0}`
- Exact overlap with other external source: 0
- Normalized overlap with other external source: 41
- Host overlap with other external source: 41

The source is retained as an external benchmark with these overlaps disclosed; it is not described as completely leakage-free.
