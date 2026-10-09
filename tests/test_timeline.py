"""Tests for the analysis layer, watch.timeline.

This file is what remains of tests/test_render.py after the page generator was
removed. Every test here is about the log and what it means, not about how it
is displayed: which fields count as identity, what counts as a change, when a
stability claim is honest. The 31 rendering tests were deleted with the page.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from watch.timeline import (  # noqa: E402
    IDENTITY_FIELDS,
    UNREADABLE,
    by_vendor,
    find_changes,
    load,
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


def test_heartbeat_records_are_not_vendors():
    rows = ROWS + [rec("__heartbeat__", "2026-10-15T06:00:00+00:00")]
    assert "__heartbeat__" not in by_vendor(rows)


def test_failed_http_is_excluded_from_change_detection():
    rows = [rec("v", "t1", measurement="aaa"),
            rec("v", "t2", http_status=500, measurement="zzz")]
    assert find_changes(rows) == []


def test_nonce_is_stripped_from_the_displayed_source():
    """A per-run nonce is not part of the endpoint's identity."""
    assert strip_query("https://api.confidential.ai/attestation?nonce=abc") == \
        "https://api.confidential.ai/attestation"
    assert strip_query("https://api.ppq.ai/attestation") == "https://api.ppq.ai/attestation"


def test_tcb_is_tracked_as_identity():
    """TCB moves on microcode updates and is what CVEs map against. A log that
    does not track it cannot connect to the attack corpus."""
    assert "tcb_version" in IDENTITY_FIELDS
    assert "tcb_reference" in IDENTITY_FIELDS


def test_tcb_change_is_reported_as_a_change():
    rows = [rec("v", "t1", tcb_version="0b01050000000000"),
            rec("v", "t2", tcb_version="0b01060000000000")]
    changes = find_changes(rows)
    assert len(changes) == 1
    assert changes[0].field == "tcb_version"


def test_load_skips_corrupt_lines(tmp_path: Path):
    f = tmp_path / "o.jsonl"
    f.write_text('{"vendor":"a","observed_at":"t"}\nnot json\n{"vendor":"b","observed_at":"t"}\n')
    assert [r["vendor"] for r in load(f)] == ["a", "b"]


def test_capability_fields_are_not_identity_so_they_do_not_fake_drift():
    """What a provider *offers* changing is not the same as its deployment
    changing. Only the second should read as drift."""
    for offered in ("e2ee_versions", "serving_role", "receipt_key_algos"):
        assert offered not in IDENTITY_FIELDS