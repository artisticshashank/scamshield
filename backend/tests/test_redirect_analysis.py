import json

import pytest

from core.redirect_analysis import (
    RedirectLimits,
    RedirectResponse,
    RedirectResolver,
    blocked_ip_reason,
)
from core.risk_fusion import SignalResult, SignalStatus, build_scan_result, fuse_signals


PUBLIC = {
    "short.example": ["93.184.216.34"],
    "tracking.example": ["93.184.216.35"],
    "final.example": ["93.184.216.36"],
}


def resolver(routes, *, ips=None, limits=None, calls=None):
    def lookup(host):
        return (ips or PUBLIC).get(host, ["93.184.216.34"])

    def request(url, ip, port, timeout, max_headers):
        if calls is not None:
            calls.append((url, ip, port, timeout, max_headers))
        return routes.get(url, RedirectResponse(200, {}))

    return RedirectResolver(resolve_ips=lookup, request=request, limits=limits or RedirectLimits())


def test_no_redirect_and_final_url_are_recorded() -> None:
    result = resolver({}).resolve("https://final.example/path")

    assert result.status == "completed"
    assert result.final_url == "https://final.example/path"
    assert result.hop_count == 1
    assert result.chain[0]["status"] == 200


def test_absolute_relative_and_protocol_relative_redirects() -> None:
    routes = {
        "https://short.example/start": RedirectResponse(302, {"Location": "/next"}),
        "https://short.example/next": RedirectResponse(301, {"Location": "//tracking.example/path"}),
        "https://tracking.example/path": RedirectResponse(302, {"Location": "https://final.example/done"}),
    }
    result = resolver(routes).resolve("https://short.example/start")

    assert result.final_url == "https://final.example/done"
    assert result.hop_count == 4
    assert result.cross_domain_redirect is True
    assert [hop["destination_url"] for hop in result.chain[:-1]] == [
        "https://short.example/next",
        "https://tracking.example/path",
        "https://final.example/done",
    ]


def test_shortener_is_reused_from_feature_extraction() -> None:
    result = resolver({}).resolve("https://bit.ly/abc")

    assert result.shortened_url is True
    assert result.derived_signals[0]["signal"] == "shortener_used"


def test_loop_and_hop_limit_are_bounded() -> None:
    loop_routes = {
        "https://tracking.example/a": RedirectResponse(302, {"Location": "/b"}),
        "https://tracking.example/b": RedirectResponse(302, {"Location": "/a"}),
    }
    loop = resolver(loop_routes).resolve("https://tracking.example/a")
    assert loop.status == "loop"
    assert loop.loop_detected is True

    routes = {
        f"https://tracking.example/{index}": RedirectResponse(
            302, {"Location": f"/{index + 1}"}
        )
        for index in range(5)
    }
    limited = resolver(routes, limits=RedirectLimits(max_hops=2, max_chain_entries=2)).resolve(
        "https://tracking.example/0"
    )
    assert limited.status == "hop_limit"
    assert limited.hop_count == 2


@pytest.mark.parametrize(
    "value",
    [
        "0.0.0.0",
        "10.1.2.3",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.168.1.1",
        "224.0.0.1",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
    ],
)
def test_private_special_and_mapped_addresses_are_blocked(value: str) -> None:
    assert blocked_ip_reason(value) is not None


def test_blocked_hostname_is_never_contacted_and_all_ips_are_checked() -> None:
    calls = []
    result = resolver(
        {},
        ips={"internal.example": ["93.184.216.34", "192.168.1.10"]},
        calls=calls,
    ).resolve("https://internal.example/")

    assert result.status == "blocked"
    assert result.blocked_destination is True
    assert calls == []


def test_localhost_and_unsupported_schemes_are_rejected_before_request() -> None:
    calls = []
    instance = resolver({}, calls=calls)
    localhost = instance.resolve("http://localhost/admin")
    file_url = instance.resolve("file:///etc/passwd")

    assert localhost.status == "blocked"
    assert file_url.status == "failed"
    assert calls == []


def test_dns_rebinding_defense_connects_only_to_validated_ip() -> None:
    calls = []
    result = resolver({}, ips={"public.example": ["93.184.216.34"]}, calls=calls).resolve(
        "https://public.example/"
    )

    assert result.status == "completed"
    assert calls[0][1] == "93.184.216.34"


def test_timeout_http_error_and_malformed_location_are_explicit() -> None:
    def timeout(*args):
        raise TimeoutError

    timed_out = RedirectResolver(
        resolve_ips=lambda _: ["93.184.216.34"],
        request=timeout,
    ).resolve("https://final.example/")
    assert timed_out.status == "timeout"
    assert timed_out.timeout is True

    malformed = resolver(
        {"https://final.example/": RedirectResponse(302, {"Location": "javascript:alert(1)"})}
    ).resolve("https://final.example/")
    assert malformed.status == "failed"
    assert malformed.chain[0]["blocked"] is True


def test_header_limit_and_total_timeout_are_forwarded_and_bodies_are_not_stored() -> None:
    calls = []
    result = resolver(
        {},
        calls=calls,
        limits=RedirectLimits(max_header_bytes=512, total_timeout_seconds=4),
    ).resolve("https://final.example/")

    assert calls[0][4] == 512
    assert "body" not in result.to_dict()
    json.dumps(result.to_dict())


def test_redirect_signal_is_available_only_when_result_is_usable() -> None:
    redirect = resolver({}).resolve("https://final.example/")
    signal = SignalResult(SignalStatus.AVAILABLE, redirect.to_dict(), redirect.risk_score)
    fused = fuse_signals(redirect=signal)
    assert fused.score_breakdown.redirect_score == redirect.risk_score
    assert "redirect" in fused.score_breakdown.available_signal_weights

    scan = build_scan_result("https://final.example/", redirect=signal)
    assert scan.redirect_result.status == SignalStatus.AVAILABLE
    json.dumps(scan.to_dict())
