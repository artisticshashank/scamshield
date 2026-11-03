"""Structural checks for the human-curated URL/message/QR demonstration corpus."""

import json
from collections import Counter
from pathlib import Path


CORPUS_PATH = Path(__file__).parents[1] / "data" / "demo_test_corpus.json"


def test_demo_corpus_has_all_three_categories_and_input_modalities() -> None:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    samples = corpus["samples"]
    counts = Counter(item["reference_category"] for item in samples)

    assert counts == {"genuine": 4, "suspicious": 4, "dangerous": 4}
    assert len({item["id"] for item in samples}) == len(samples)
    assert all(item["url"].startswith(("http://", "https://")) for item in samples)
    assert all(item["qr_payload"] == item["url"] for item in samples)
    assert all(item["qr_asset"].endswith(f'{item["id"]}.svg') for item in samples)
    assert len({item["qr_asset"] for item in samples}) == len(samples)
    assert all(item["message"].strip() for item in samples)
    assert all(item["rationale"].strip() for item in samples)


def test_suspicious_and_dangerous_demo_domains_are_non_routable() -> None:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    for item in corpus["samples"]:
        if item["reference_category"] in {"suspicious", "dangerous"}:
            assert item["url"].split("/")[2].endswith((".example", ".invalid"))


def test_corpus_explicitly_warns_that_reference_labels_are_not_predictions() -> None:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert "not guaranteed predictions" in corpus["purpose"]
