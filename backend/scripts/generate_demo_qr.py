"""Generate one printable QR sample per reference verdict category.

Run from the backend directory:
    python scripts/generate_demo_qr.py

The generated QR codes contain only the URLs in demo_test_corpus.json.
Suspicious/dangerous examples use reserved non-routable domains.
"""

import json
from pathlib import Path

import qrcode
from qrcode.image.svg import SvgPathImage


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "data" / "demo_test_corpus.json"
OUTPUT = ROOT / "data" / "qr"


def main() -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    OUTPUT.mkdir(parents=True, exist_ok=True)
    generated = []
    for category in ("genuine", "suspicious", "dangerous"):
        sample = next(
            item for item in corpus["samples"]
            if item["reference_category"] == category
        )
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4,
        )
        qr.add_data(sample["qr_payload"])
        qr.make(fit=True)
        image = qr.make_image(image_factory=SvgPathImage)
        destination = OUTPUT / f"{category}.svg"
        image.save(destination)
        generated.append(destination)
    for path in generated:
        print(f"Generated {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
