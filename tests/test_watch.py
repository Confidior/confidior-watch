"""Tests for confidior-watch. No network access; every fetcher is injected."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from watch.collector import (  # noqa: E402
    Observation,
    anchor_digest_soft,
    append_to_log,
    collect,
    day_digest,
    heartbeat,
)
from watch.sources import (  # noqa: E402
    Source,
    default_sources,
    parse_dstack,
    parse_nsm_cose,
)

# ---------------------------------------------------------------------------
# Parsers, against shapes captured live 2026-10-09.
# ---------------------------------------------------------------------------

DSTACK_SAMPLE = {
    "api_version": "aci/1",
    "workload_keyset_digest": "sha256:ef8a03c0c5e349310394c0d5865f766f8a1258f1acdb5fcb6ed2ebcd757e5f5a",
    "attestation": {
        "tee_type": "tdx",
        "workload_keyset": {"not_after": 1792250755},
        "source_provenance": {
            "repo_url": "https://github.com/Dstack-TEE/private-ai-gateway.git",
            "repo_commit": "8d0a666a2418898a8c823a9af49a634edd122a64",
        },
        "evidence": {
            "event_log": json.dumps(
                [
                    {"event": "compose-hash", "event_payload": "0637b3d506c80c0328c84697c290f5fb"},
                    {"event": "os-image-hash", "event_payload": "bd369a8c2f9edb2b52dad48ac8e0b32d"},
                    {"event": "app-id", "event_payload": "fdb7a14e5a6675f752e2cb69c9067a98"},
                    {"event": "instance-id", "event_payload": "CHANGES-EVERY-RESTART"},
                ]
            )
        },
    },
}


def test_parse_dstack_extracts_named_events():
    (obs,) = parse_dstack(DSTACK_SAMPLE)
    assert obs["measurement"] == "0637b3d506c80c0328c84697c290f5fb"
    assert obs["os_image_hash"] == "bd369a8c2f9edb2b52dad48ac8e0b32d"
    assert obs["app_id"] == "fdb7a14e5a6675f752e2cb69c9067a98"
    assert obs["keyset_digest"].startswith("sha256:ef8a03c0")


def test_keyset_digest_and_commit_are_per_observation_identity():
    """The two fields that make cross-vendor sameness visible rather than hidden."""
    (obs,) = parse_dstack(DSTACK_SAMPLE)
    assert obs["keyset_digest"] == DSTACK_SAMPLE["workload_keyset_digest"]
    assert obs["repo_commit"] == "8d0a666a2418898a8c823a9af49a634edd122a64"


def test_instance_id_is_not_recorded_as_identity():
    """instance-id changes every restart. Recording it would be constant false drift."""
    (obs,) = parse_dstack(DSTACK_SAMPLE)
    assert "CHANGES-EVERY-RESTART" not in json.dumps(obs)


def test_parse_dstack_records_note_when_identity_missing():
    (obs,) = parse_dstack({"api_version": "aci/1", "attestation": {}})
    assert obs["note"] == "no identity field located in payload"


def test_parse_dstack_survives_malformed_shapes():
    for bad in [None, [], "string", {"attestation": "not-a-dict"}, {"attestation": None}]:
        out = parse_dstack(bad)
        assert out and isinstance(out[0], dict)  # never raises, always returns


def test_parse_dstack_tolerates_corrupt_event_log():
    payload = {"attestation": {"evidence": {"event_log": "{not json"}}}
    (obs,) = parse_dstack(payload)
    assert obs["measurement"] == ""  # degrades, does not crash


NSM_SAMPLE = {
    "attestation_document_b64": "aGVsbG8gd29ybGQ=",  # b"hello world"
    "cert_spki_sha256": "642eda68cc9e0c91be6c029590f00129f8ad069746618c646373937a9cccde39",
    "format": "nsm-cose-sign1",
    "hpke_public_key": "ea2cb8a9",
}


def test_parse_nsm_cose_hashes_the_document():
    (obs,) = parse_nsm_cose(NSM_SAMPLE)
    assert obs["platform"] == "aws-nitro"
    assert obs["doc_format"] == "nsm-cose-sign1"
    assert obs["doc_bytes"] == str(len(b"hello world"))
    assert len(obs["measurement"]) == 64  # sha256 hex
    assert obs["cert_spki_sha256"].startswith("642eda68")


def test_parse_nsm_cose_rejects_bad_base64():
    (obs,) = parse_nsm_cose({"attestation_document_b64": "!!!not base64!!!"})
    assert "not valid base64" in obs["note"]


# ---------------------------------------------------------------------------
# Collection: the properties the doc asks for.
# ---------------------------------------------------------------------------


def test_collect_records_http_status_as_data_not_exception():
    """A dead source is a finding. It must not abort the run."""
    src = Source(vendor="dead", url="https://example.invalid/x", parse=parse_dstack)
    (obs,) = collect([src], fetcher=lambda u: (404, b""))
    assert obs.http_status == 404
    assert "status 404" in obs.note


def test_collect_survives_network_failure():
    src = Source(vendor="down", url="https://example.invalid/x", parse=parse_dstack)
    (obs,) = collect([src], fetcher=lambda u: (0, b""))
    assert obs.http_status == 0


def test_collect_survives_parser_exception():
    def explode(_payload):
        raise RuntimeError("boom")

    src = Source(vendor="bad", url="https://x", parse=explode)
    (obs,) = collect([src], fetcher=lambda u: (200, b"{}"))
    assert "parser error" in obs.note


def test_collect_survives_non_json_body():
    src = Source(vendor="html", url="https://x", parse=parse_dstack)
    (obs,) = collect([src], fetcher=lambda u: (200, b"<html>not json</html>"))
    assert "decode failed" in obs.note


def test_collect_does_not_parse_non_200_body():
    """A 426 body is a rejection notice, not evidence. Do not parse it."""
    src = Source(vendor="tinfoil", url="https://x", parse=parse_dstack)
    (obs,) = collect([src], fetcher=lambda u: (426, DSTACK_SAMPLE and json.dumps(DSTACK_SAMPLE).encode()))
    assert obs.http_status == 426
    assert obs.measurement == ""


def test_collect_hashes_raw_response():
    src = Source(vendor="v", url="https://x", parse=parse_dstack)
    body = json.dumps(DSTACK_SAMPLE).encode()
    (obs,) = collect([src], fetcher=lambda u: (200, body))
    import hashlib

    assert obs.response_sha256 == hashlib.sha256(body).hexdigest()


def test_collect_fills_platform_from_source_when_parser_is_silent():
    src = Source(vendor="v", url="https://x", parse=lambda p: [{"measurement": "abc"}], platform="intel-tdx")
    (obs,) = collect([src], fetcher=lambda u: (200, b"{}"))
    assert obs.platform == "intel-tdx"


def test_collect_is_deterministic_for_a_fixed_response():
    src = Source(vendor="v", url="https://x", parse=parse_dstack)
    body = json.dumps(DSTACK_SAMPLE).encode()
    a = collect([src], fetcher=lambda u: (200, body), observed_at="2026-10-09T00:00:00+00:00")
    b = collect([src], fetcher=lambda u: (200, body), observed_at="2026-10-09T00:00:00+00:00")
    assert [o.to_json() for o in a] == [o.to_json() for o in b]


def test_heartbeat_names_the_vendors_seen():
    obs = [Observation(observed_at="t", vendor="redpill"), Observation(observed_at="t", vendor="ppq")]
    hb = heartbeat(obs, "t")
    assert hb.vendor == "__heartbeat__"
    assert "2 observations across 2 vendors" in hb.note


def test_default_sources_is_capped_and_never_grows_silently():
    """Depth over breadth. Growing this list is a deliberate act with a cost."""
    assert len(default_sources()) <= 8
    assert {s.vendor for s in default_sources()} == {"redpill", "phala", "ppq"}


# ---------------------------------------------------------------------------
# Log and anchoring.
# ---------------------------------------------------------------------------


def test_append_to_log_is_append_only(tmp_path: Path):
    log = tmp_path / "observations.jsonl"
    o1 = Observation(observed_at="2026-10-09T00:00:00+00:00", vendor="a", measurement="m1")
    o2 = Observation(observed_at="2026-10-09T01:00:00+00:00", vendor="a", measurement="m2")
    append_to_log(log, [o1])
    append_to_log(log, [o2])
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["measurement"] == "m1"
    assert json.loads(lines[1])["measurement"] == "m2"


def test_day_digest_is_reproducible_and_content_addressed(tmp_path: Path):
    f = tmp_path / "d.jsonl"
    f.write_text('{"a":1}\n')
    d1 = day_digest([f])
    assert d1 == day_digest([f])  # stable
    f.write_text('{"a":2}\n')
    assert day_digest([f]) != d1  # tamper-evident


def test_day_digest_of_missing_file_is_empty(tmp_path: Path):
    assert day_digest([tmp_path / "nope.jsonl"]) == ""


def test_anchor_fails_soft_so_the_observation_is_never_lost():
    def offline(_digest):
        raise RuntimeError("rekor unreachable")

    result = anchor_digest_soft("abc123", anchor=offline)
    assert result["anchored"] is False
    assert "rekor unreachable" in result["reason"]


def test_anchor_reports_success():
    result = anchor_digest_soft("abc123", anchor=lambda d: {"uuid": "u-1", "log_index": 42})
    assert result["anchored"] is True
    assert result["rekor"]["log_index"] == 42


def test_anchor_of_empty_digest_is_skipped():
    assert anchor_digest_soft("")["anchored"] is False


# ---------------------------------------------------------------------------
# Vendored Rekor: must not import the engine.
# ---------------------------------------------------------------------------


def test_vendored_rekor_does_not_import_the_engine():
    """The clock must not depend on anything that moves."""
    src = (Path(__file__).resolve().parents[1] / "watch" / "rekor_vendored.py").read_text()
    assert "confidior_engine" not in src
    assert "src.export" not in src
    assert "VENDORED_FROM" in src  # provenance is recorded, not implied
