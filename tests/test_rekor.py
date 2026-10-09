"""Tests for the vendored Rekor anchoring path.

These exercise the code that makes the log tamper-evident, which had no test at
all: every branch of watch/rekor_vendored.py was uncovered. Nothing here touches
the network. The two injection points the module already exposes, ``poster`` and
``url_fetcher``, stand in for Sigstore.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from watch.rekor_vendored import (  # noqa: E402
    MAX_ATTESTATION_SIZE,
    RekorError,
    _make_ephemeral_ecdsa_cert,
    anchor_digest,
    build_hashedrekord_entry,
    get_rekor_url,
    submit_entry,
)


def _url_fetcher(_url: str) -> dict:
    return {"rekorTlogUrls": [{"url": "https://rekor.example"}]}


# --- the entry that gets submitted ------------------------------------------


def test_hashedrekord_entry_carries_the_hash_and_never_the_payload():
    """Rekor stores a hash. The payload itself must not appear in the entry."""
    payload = b"the secret the log must never publish"
    entry = build_hashedrekord_entry(payload, b"sig", b"-----BEGIN CERT-----")
    assert entry["kind"] == "hashedrekord"
    blob = json.dumps(entry)
    assert "secret" not in blob
    assert entry["spec"]["data"]["hash"]["algorithm"] == "sha256"
    assert len(entry["spec"]["data"]["hash"]["value"]) == 64


def test_hashedrekord_entry_hash_matches_the_payload():
    import hashlib

    entry = build_hashedrekord_entry(b"abc", b"s", b"k")
    assert entry["spec"]["data"]["hash"]["value"] == hashlib.sha256(b"abc").hexdigest()


# --- discovering the log URL -----------------------------------------------


def test_get_rekor_url_reads_the_first_tlog_url():
    assert get_rekor_url(fetcher=_url_fetcher) == "https://rekor.example"


def test_get_rekor_url_raises_when_the_config_has_no_urls():
    with pytest.raises(RekorError):
        get_rekor_url(fetcher=lambda _u: {"rekorTlogUrls": []})


def test_get_rekor_url_wraps_a_network_failure_as_rekor_error():
    import urllib.error

    def boom(_u):
        raise urllib.error.URLError("no route")

    with pytest.raises(RekorError):
        get_rekor_url(fetcher=boom)


# --- submitting ------------------------------------------------------------


def test_submit_entry_returns_the_entry_keyed_by_uuid():
    out = submit_entry(
        {"a": 1}, "https://rekor.example", poster=lambda _u, _b: {"uuid-1": {"logIndex": 7}}
    )
    assert out["uuid"] == "uuid-1"
    assert out["logIndex"] == 7


def test_submit_entry_refuses_an_oversized_body():
    """The public instance has a size limit; an oversized entry must be refused
    here rather than sent and rejected with an opaque error."""
    huge = {"pad": "x" * (MAX_ATTESTATION_SIZE + 1)}
    with pytest.raises(RekorError):
        submit_entry(huge, "https://rekor.example", poster=lambda _u, _b: {})


def test_submit_entry_wraps_a_submission_failure_as_rekor_error():
    import urllib.error

    def boom(_u, _b):
        raise urllib.error.HTTPError("u", 500, "server error", {}, None)

    with pytest.raises(RekorError):
        submit_entry({"a": 1}, "https://rekor.example", poster=boom)


# --- the signing material --------------------------------------------------


def test_ephemeral_cert_is_a_pem_certificate_not_a_key():
    key, pem = _make_ephemeral_ecdsa_cert()
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY" not in pem  # the key must not travel with it
    assert key.key_size == 256


def test_each_call_makes_a_fresh_key():
    """The key exists only to sign one submission and is discarded. Two calls
    must not produce the same one.

    Compared on the key itself, not on the certificate: an ECDSA signature is
    randomised, so two certificates signed by the *same* key still differ byte
    for byte, and a PEM comparison would pass while the key was reused.
    """
    key_a, _ = _make_ephemeral_ecdsa_cert()
    key_b, _ = _make_ephemeral_ecdsa_cert()
    assert key_a.private_numbers().private_value != key_b.private_numbers().private_value


# --- end to end ------------------------------------------------------------


def test_anchor_digest_returns_the_log_index_and_uuid():
    result = anchor_digest(
        "ab" * 32,
        url_fetcher=_url_fetcher,
        poster=lambda _u, _b: {"uuid-9": {"logIndex": 99}},
    )
    assert result == {"log_index": 99, "uuid": "uuid-9"}


def test_anchor_digest_uses_the_url_it_discovered():
    """The url_fetcher and the poster must see the same log: a mismatch would
    submit to one instance and record the index from another."""
    seen = {}

    def poster(url, _body):
        seen["url"] = url
        return {"u": {"logIndex": 1}}

    anchor_digest("cd" * 32, url_fetcher=_url_fetcher, poster=poster)
    assert seen["url"] == "https://rekor.example/api/v1/log/entries"


def test_anchor_digest_posts_a_wellformed_hashedrekord_body():
    captured = {}

    def poster(_url, body):
        captured["body"] = json.loads(body)
        return {"u": {"logIndex": 1}}

    anchor_digest("ef" * 32, url_fetcher=_url_fetcher, poster=poster)
    body = captured["body"]
    assert body["kind"] == "hashedrekord"
    assert body["spec"]["signature"]["publicKey"]["content"]  # the cert is attached
