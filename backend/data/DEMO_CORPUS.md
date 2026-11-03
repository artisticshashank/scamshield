# ScamShield demo corpus

The file `demo_test_corpus.json` contains 12 curated demo inputs: four each for
`genuine`, `suspicious`, and `dangerous`. Every case includes a URL, a
message containing that URL, and a QR payload that decodes to the same URL.

## Generate the QR images

From the repository root:

```bash
cd backend
python -m pip install -r requirements.txt
python scripts/generate_demo_qr.py
```

This writes 12 printable SVG QR codes (one per corpus case) to:

- `backend/data/qr/`
- `frontend/public/demo-qr/`

The frontend can then display and upload the matching QR example for each category. Each of the 12 records has its own QR asset. QR images encode
only the URL in the matching corpus case; they do not open or visit that URL.

## Safety and interpretation

- Suspicious and dangerous sample hosts use reserved `.example` and `.invalid`
  domains. They are intentionally non-routable examples, not live phishing sites.
- Genuine examples use established public websites. A site's status can change;
  a familiar brand name is not a guarantee that a particular link is safe.
- The reference category is a human-curated test label. It is not a promise that
  the current model or risk-fusion pipeline will produce that verdict.
- Do not use this small demonstration corpus as a training set or claim benchmark
  accuracy from it. Keep training, validation, and held-out test data separate.
- A QR code is only a container for text. Decode it first, then analyze the
  destination; never open a decoded destination automatically.

## What the examples demonstrate

| Category | Typical signals | User guidance |
|---|---|---|
| Genuine | Familiar public domain, neutral context | Still check the exact hostname |
| Suspicious | Unverified domain, login/verification or delivery wording | Verify through the organization's official app/site |
| Dangerous | Urgent pressure, credential/PIN/payment request, deceptive hostname | Do not open, pay, or share credentials |

SHAP explanations are generated only when the fitted URL classifier is loaded.
They explain the model's character n-gram features in log-odds space and do not
alter the final 0–100 risk score. Missing SHAP must not prevent a scan.
