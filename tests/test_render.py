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


def test_page_colours_come_from_the_engine_badge():
    """Same brand as the badge and the site, not a separate project.

    The expected values are read from src/export/badge.py, which
    docs/the internal design note names as the source of truth for the visual
    language. An earlier version of this test hardcoded its own copies, so it
    passed while the page drifted to a different accent and surface ramp. A
    test that restates the values it is meant to check cannot catch drift.
    """
    badge = _engine_badge_colours()
    if not badge:
        import pytest

        pytest.skip("engine badge.py not importable from this checkout")

    html = render(ROWS, generated_at="t")
    for name, hex_value in badge.items():
        assert f"--{name}:{hex_value}" in html, (
            f"page token --{name} does not match badge.py ({hex_value})"
        )
    # Sourced from badge.py's own panel/text ramp.
    assert "--bg-panel:#161822" in html
    assert "--container:1120px" in html


def _engine_badge_colours() -> dict[str, str]:
    """Read the canonical colours out of the engine's badge module.

    Parsed as text rather than imported: the watch repo must not take a hard
    dependency on the engine, and it must still run when the engine is absent.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "confidior-engine" / "src" / "export" / "badge.py"
    if not root.exists():
        return {}
    text = root.read_text()
    wanted = {"green": "_GREEN", "red": "_RED", "amber": "_AMBER", "blue": "_BLUE"}
    found: dict[str, str] = {}
    for token, const in wanted.items():
        m = re.search(rf'^{const}\s*=\s*"(#[0-9a-fA-F]{{6}})"', text, re.M)
        if m:
            found[token] = m.group(1).lower()
    return found


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


def test_full_response_hash_is_shown_not_truncated():
    """A truncated hash cannot be compared to anything. It is decoration.

    The hash lives in the collapsed body now, keyed by its field name, and it
    is printed whole.
    """
    rows = [rec("v", "t1", measurement="m", response_sha256="a" * 64)]
    html = render(rows, generated_at="t")
    assert "response_sha256" in html
    assert "a" * 64 in html
    assert "a" * 63 + "&hellip;" not in html


def test_every_observation_is_collapsible():
    """One <details> per observation, so none is dropped from the page."""
    rows = [rec("v", f"2026-10-0{i}T06:00:00+00:00", measurement=f"m{i}")
            for i in range(1, 4)]
    html = render(rows, generated_at="t")
    assert html.count('<details class="obs">') == 3


def test_no_observation_is_silently_capped():
    """The page used to print only the last 12 rows. All of them belong."""
    rows = [rec("v", f"2026-10-{i:02d}T06:00:00+00:00", measurement=f"m{i}")
            for i in range(1, 20)]
    html = render(rows, generated_at="t")
    assert html.count('<details class="obs">') == 19


def test_collapsible_body_carries_every_field_recorded():
    """All its details, not a curated subset: a field the run stored is a fact
    the page must be able to show."""
    rows = [rec("v", "t1", measurement="m", some_obscure_field="kept")]
    html = render(rows, generated_at="t")
    assert "some_obscure_field" in html
    assert "kept" in html


def test_newest_observation_is_first_on_the_page():
    rows = [rec("v", "2026-10-01T06:00:00+00:00", measurement="OLD"),
            rec("v", "2026-10-09T06:00:00+00:00", measurement="NEW")]
    html = render(rows, generated_at="t")
    assert html.index("NEW") < html.index("OLD")


def test_each_row_links_to_the_source_so_a_reader_can_recheck():
    rows = [rec("v", "t1", measurement="m", source_url="https://api.example/x")]
    html = render(rows, generated_at="t")
    assert 'href="https://api.example/x"' in html
    assert "re-fetch" in html


def test_page_explains_what_each_check_means():
    """The legend explains column headers, so it belongs once -- not repeated
    inside every vendor card, where identical text is just noise."""
    html = _flat(render(ROWS, generated_at="t"))
    assert "What each check means" in html
    # The check descriptions appear exactly once, in the single legend block.
    assert html.count("CVEs map against") == 1
    assert html.count("Intel's PCK") == 1


def test_tcb_is_tracked_as_identity():
    """TCB moves on microcode updates and is what CVEs map against. A log that
    does not track it cannot connect to the attack corpus."""
    from watch.render import IDENTITY_FIELDS

    assert "tcb_version" in IDENTITY_FIELDS
    assert "tcb_reference" in IDENTITY_FIELDS


def test_tcb_change_is_reported_as_a_change():
    rows = [rec("v", "t1", tcb_version="0b01050000000000"),
            rec("v", "t2", tcb_version="0b01060000000000")]
    changes = find_changes(rows)
    assert len(changes) == 1
    assert changes[0].field == "tcb_version"


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


# --- measured surface -------------------------------------------------------


def test_surface_shows_published_fields_and_counts_them():
    rows = [rec("v", "t1", serving_role="aggregator", e2ee_versions="2",
                receipt_key_algos="ed25519", receipt_key_count="1")]
    html = _flat(render(rows, generated_at="t"))
    assert "Measured surface" in html
    assert "aggregator" in html
    assert "fields published" in html


def test_empty_gpu_evidence_is_shown_with_its_reason():
    """An empty evidence list is a finding; the reason is the useful part."""
    from watch.render import _count_word

    assert _count_word("0", "protocol serves no gpu field") == \
        "none published (protocol serves no gpu field)"
    assert _count_word("3", "") == "3"
    assert _count_word("", "") == ""


def test_unpublished_fields_are_counted_not_hidden():
    """A provider publishing 12 of 28 fields is the interesting fact."""
    from watch.render import _fmt_keys

    assert _fmt_keys("", "") == ""
    assert _fmt_keys("ed25519", "1") == "1: ed25519"
    assert _fmt_keys("", "0") == "0"


def test_surface_reports_nothing_readable_rather_than_a_blank_table():
    rows = [rec("v", "t1", http_status=500, note="fetch returned status 500")]
    html = _flat(render(rows, generated_at="t"))
    assert "Nothing readable was published" in html


def test_capability_fields_are_not_identity_so_they_do_not_fake_drift():
    """What a provider *offers* changing is not the same as its deployment
    changing. Only the second should read as drift."""
    from watch.render import IDENTITY_FIELDS

    for offered in ("e2ee_versions", "serving_role", "receipt_key_algos"):
        assert offered not in IDENTITY_FIELDS
