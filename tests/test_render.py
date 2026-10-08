"""Tests for the timeline page. The page's honesty is a testable property."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from watch.render import (  # noqa: E402
    by_vendor,
    find_changes,
    load,
    render,
    stability,
    strip_query,
)


def rec(vendor, at, **kw):
    base = {"vendor": vendor, "observed_at": at, "http_status": 200, "source_url": "https://x"}
    base.update(kw)
    return base


ROWS = [
    rec("redpill", "2026-10-01T06:00:00+00:00", measurement="aaa", os_image_hash="os1"),
    rec("redpill", "2026-10-08T06:00:00+00:00", measurement="aaa", os_image_hash="os1"),
    rec("redpill", "2026-10-15T06:00:00+00:00", measurement="bbb", os_image_hash="os1"),
]


def test_changes_detects_only_identity_fields():
    changes = find_changes(ROWS)
    assert len(changes) == 1
    assert changes[0].field == "measurement"
    assert changes[0].before == "aaa" and changes[0].after == "bbb"


def test_response_hash_change_is_not_identity_drift():
    """The raw response hash moves on any byte. It must never read as a redeploy."""
    rows = [rec("v", "t1", measurement="same", response_sha256="h1"),
            rec("v", "t2", measurement="same", response_sha256="h2")]
    assert find_changes(rows) == []


def test_empty_identity_never_reads_as_a_change():
    """A failed parse must not fabricate drift."""
    rows = [rec("v", "t1", measurement="aaa"), rec("v", "t2", measurement="")]
    assert find_changes(rows) == []


def test_stability_reports_the_last_change():
    since, count = stability(ROWS)
    assert since == "2026-10-15T06:00:00+00:00"
    assert count == 3


def test_stability_falls_back_to_first_observation():
    rows = [rec("v", "2026-10-01T06:00:00+00:00", measurement="aaa"),
            rec("v", "2026-10-08T06:00:00+00:00", measurement="aaa")]
    since, count = stability(rows)
    assert since == "2026-10-01T06:00:00+00:00"
    assert count == 2


def test_single_observation_is_not_reported_as_stable():
    """One observation is not a stability claim. Day one is when people look."""
    rows = [rec("v", "2026-10-01T06:00:00+00:00", measurement="aaa")]
    since, count = stability(rows)
    assert count == 1
    html = _flat(render(rows, generated_at="t"))
    assert "first observed" in html
    assert "nothing to compare against yet" in html
    assert "unchanged since" not in html


def test_two_observations_licenses_the_unchanged_wording():
    rows = [rec("v", "2026-10-01T06:00:00+00:00", measurement="aaa"),
            rec("v", "2026-10-08T06:00:00+00:00", measurement="aaa")]
    html = _flat(render(rows, generated_at="t"))
    assert "unchanged since" in html
    assert "2 observations" in html


def test_heartbeat_records_are_not_vendors():
    rows = ROWS + [rec("__heartbeat__", "2026-10-15T06:00:00+00:00")]
    assert "__heartbeat__" not in by_vendor(rows)


def test_failed_http_is_excluded_from_change_detection():
    rows = [rec("v", "t1", measurement="aaa"),
            rec("v", "t2", http_status=500, measurement="zzz")]
    assert find_changes(rows) == []


def _flat(html: str) -> str:
    """Collapse whitespace; the page is assembled from wrapped string parts."""
    return " ".join(html.split())


def test_page_states_it_does_not_grade():
    html = _flat(render(ROWS, generated_at="2026-10-15T00:00:00+00:00"))
    assert "does not grade" in html
    assert "no verdict" in html.lower()


def test_page_states_no_uptime_commitment():
    html = _flat(render(ROWS, generated_at="2026-10-15T00:00:00+00:00"))
    assert "not a service" in html
    assert "no uptime commitment" in html


def test_page_uses_the_dotcom_design_tokens():
    """Same brand as confidior.com, not a separate project."""
    html = render(ROWS, generated_at="t")
    for token in ["--bg:#0b0d14", "--bg-panel:#161822", "--accent:#7b8cff",
                  "--green:#4dc729", "--red:#df3c30", "--container:1120px"]:
        assert token in html, f"missing design token {token}"


def test_body_text_uses_sans_and_only_machine_values_use_mono():
    """DESIGN.md 1.4: mono means machine truth. Using it everywhere destroys the signal."""
    html = render(ROWS, generated_at="t")
    assert "font-family:var(--sans)" in html
    # the body rule must not be monospace
    body_rule = html.split("body{")[1].split("}")[0]
    assert "var(--mono)" not in body_rule


def test_empty_log_says_so_rather_than_looking_healthy():
    html = _flat(render([], generated_at="2026-10-15T00:00:00+00:00"))
    assert "No observations yet" in html
    assert "silence never reads as a claim" in html


def test_unreadable_source_is_shown_not_hidden():
    rows = [rec("v", "t1", http_status=426, note="fetch returned status 426")]
    html = _flat(render(rows, generated_at="t"))
    assert "426" in html
    assert "recorded, not hidden" in html


def test_nonce_is_stripped_from_the_displayed_source():
    """A per-run nonce is not part of the endpoint's identity."""
    assert strip_query("https://api.confidential.ai/attestation?nonce=abc") == \
        "https://api.confidential.ai/attestation"
    assert strip_query("https://api.ppq.ai/attestation") == "https://api.ppq.ai/attestation"


def test_page_escapes_untrusted_values():
    rows = [rec("v<script>", "t1", measurement="<img src=x onerror=alert(1)>")]
    html = _flat(render(rows, generated_at="t"))
    assert "<script>" not in html
    assert "&lt;img" in html


def test_load_skips_corrupt_lines(tmp_path: Path):
    f = tmp_path / "o.jsonl"
    f.write_text('{"vendor":"a","observed_at":"t"}\nnot json\n{"vendor":"b","observed_at":"t"}\n')
    assert [r["vendor"] for r in load(f)] == ["a", "b"]


def test_render_is_deterministic():
    a = render(ROWS, generated_at="fixed")
    b = render(ROWS, generated_at="fixed")
    assert a == b
