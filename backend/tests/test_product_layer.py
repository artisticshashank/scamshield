from concurrent.futures import ThreadPoolExecutor

import pytest

from product_layer import GuestQuotaError, IdempotencyError, ProductStore


def test_guest_quota_commits_only_successful_scans_and_retries_idempotently() -> None:
    store = ProductStore()
    guest_id, _, _ = store.guest_for(None)
    first = store.reserve(guest_id, "one", "hash-one")
    store.commit(first, {"scan_id": "one"})
    retry = store.reserve(guest_id, "one", "hash-one")
    assert retry.status == "committed"
    assert store.commit(retry, {"scan_id": "other"}) == {"scan_id": "one"}

    second = store.reserve(guest_id, "two", "hash-two")
    store.rollback(second)
    third = store.reserve(guest_id, "three", "hash-three")
    store.commit(third, {"scan_id": "three"})
    with pytest.raises(GuestQuotaError):
        store.reserve(guest_id, "four", "hash-four")


def test_guest_quota_is_race_safe() -> None:
    store = ProductStore()
    guest_id, _, _ = store.guest_for(None)

    def reserve(index: int) -> bool:
        try:
            reservation = store.reserve(guest_id, str(index), str(index))
            store.commit(reservation, {"scan_id": str(index)})
            return True
        except GuestQuotaError:
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        accepted = list(executor.map(reserve, range(8)))
    assert sum(accepted) == 2


def test_authenticated_idempotency_binds_request_to_payload() -> None:
    store = ProductStore()
    assert store.persist_user("user-a", "request-1", {"scan_id": "first"}, "https://a.example", "url") is None
    assert store.persist_user("user-a", "request-1", {"scan_id": "retry"}, "https://a.example", "url") == {
        "scan_id": "first"
    }
    with pytest.raises(IdempotencyError):
        store.persist_user("user-a", "request-1", {"scan_id": "other"}, "https://b.example", "url")
    assert store.persist_user("user-b", "request-1", {"scan_id": "user-b"}, "https://b.example", "url") is None
