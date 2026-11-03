"""Generate one printable QR code per demo corpus case.

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
OUTPUTS = (ROOT / "data" / "qr", ROOT.parent / "frontend" / "public" / "demo-qr")


def main() -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    generated = []
    for output_dir in OUTPUTS:
        output_dir.mkdir(parents=True, exist_ok=True)
    for sample in corpus["samples"]:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4,
        )
        qr.add_data(sample["qr_payload"])
        qr.make(fit=True)
        image = qr.make_image(image_factory=SvgPathImage)
        filename = f'{sample["id"]}.svg'
        for output_dir in OUTPUTS:
            destination = output_dir / filename
            image.save(destination)
            generated.append(destination)
    for path in generated:
        print(f"Generated {path.relative_to(ROOT.parent)}")


if __name__ == "__main__":
    main()
