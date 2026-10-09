"""Tinfoil (AMD SEV-SNP): predicate parsing and the REPORT_DATA binding.

All offline. The derivation under test was reverse-engineered from the
vendor's own verifier source and confirmed byte-exact against the live
endpoint on 2026-10-09:

    report_data[0:32] = sha256("https://tinfoil.sh/report-data/v1"
                              || nonce_bytes || crypto_material_hash_bytes
                              || device_evidence_hash_bytes)
"""

import base64
import gzip
import hashlib
import json

from watch.checks import check_tinfoil
from watch.sources import (
    TINFOIL_REPORT_DATA_ALG,
    default_sources,
    parse_tinfoil,
    tinfoil_url,
)

NONCE = "a" * 64
CM_HASH = hashlib.sha256(b"crypto-material").hexdigest()
DE_HASH = hashlib.sha256(b"device-evidence").hexdigest()


def _expected_report_data(nonce=NONCE, cm=CM_HASH, de=DE_HASH):
    digest = hashlib.sha256(
        TINFOIL_REPORT_DATA_ALG.encode()
        + bytes.fromhex(nonce)
        + bytes.fromhex(cm)
        + bytes.fromhex(de)
    ).hexdigest()
    return digest + "00" * 32


def _v3_doc(nonce=NONCE, cm=CM_HASH, de=DE_HASH, report_data=None, gpu_items=None):
    """A minimal v3 document shaped like the real one."""
    return {
        "format": "https://tinfoil.sh/predicate/attestation/v3",
        "challenge": {
            "nonce": nonce,
            "report_data": report_data
            if report_data is not None
            else _expected_report_data(nonce, cm, de),
        },
        "cpu_evidence": {
            "format": "https://tinfoil.sh/format/sev-snp-report/v1",
            "report_base64": "",
            "endorsed": {"crypto_material_hash": cm, "device_evidence_hash": de},
        },
        "crypto_material": base64.b64encode(
            gzip.compress(
                json.dumps(
                    {
                        "format": "https://tinfoil.sh/crypto-material/v1",
                        "items": [
                            {
                                "id": "tls",
                                "format": "https://tinfoil.sh/key/spki-fp-sha256/v1",
                                "data": "ab" * 32,
                            },
                            {
                                "id": "hpke",
                                "format": "https://tinfoil.sh/key/x25519-hpke/v1",
                                "data": "cd" * 32,
                            },
                        ],
                    }
                ).encode()
            )
        ).decode(),
        "device_evidence": base64.b64encode(
            gzip.compress(
                json.dumps(
                    {
                        "format": "https://tinfoil.sh/device-evidence/v1",
                        "items": gpu_items or [],
                    }
                ).encode()
            )
        ).decode(),
        "collateral": [
            {"id": "cpu-endorsement", "data": {"vcek_der_base64": base64.b64encode(b"x").decode()}}
        ],
    }


# --- URL / nonce ------------------------------------------------------------


def test_tinfoil_url_carries_a_full_length_hex_nonce():
    """A short nonce makes the endpoint 400, and no nonce returns the smaller
    v2 document with no evidence set at all."""
    url, nonce = tinfoil_url()
    assert len(nonce) == 64
    assert url.startswith("https://inference.tinfoil.sh/.well-known/tinfoil-attestation?nonce=")
    assert nonce in url


def test_tinfoil_is_registered_as_a_source():
    sources = {s.vendor: s for s in default_sources()}
    assert "tinfoil" in sources
    assert sources["tinfoil"].platform == "amd-sev-snp"
    assert sources["tinfoil"].check is check_tinfoil


# --- REPORT_DATA derivation -------------------------------------------------


def test_report_data_derivation_is_recomputed_and_matches():
    """The point of this source. The quote provably commits to the published
    key material, rather than the document merely asserting that it does."""
    checks = check_tinfoil(_v3_doc(), NONCE)
    assert checks.freshness_bound == "true"
    assert "recomputed" in checks.freshness_note


def test_a_forged_report_data_is_detected():
    checks = check_tinfoil(_v3_doc(report_data="ff" * 64), NONCE)
    assert checks.freshness_bound == "false"


def test_derivation_is_bound_to_the_nonce():
    """A document valid for one challenge must not validate for another."""
    doc = _v3_doc(nonce="b" * 64)
    checks = check_tinfoil(doc, NONCE)
    assert checks.freshness_bound == "false"


def test_endorsed_hashes_come_from_cpu_evidence_not_the_top_level():
    """Regression: these live under cpu_evidence.endorsed. Reading the top
    level found nothing and produced a false 'no nonce exchanged'."""
    doc = _v3_doc()
    assert "crypto_material_hash" not in doc
    assert check_tinfoil(doc, NONCE).freshness_bound == "true"


def test_absent_endorsed_hashes_do_not_claim_a_match():
    doc = _v3_doc()
    doc["cpu_evidence"]["endorsed"] = {}
    checks = check_tinfoil(doc, NONCE)
    assert checks.freshness_bound != "true"
    assert "not recomputed" in checks.freshness_note


def test_tls_spki_is_read_as_a_spki_fingerprint():
    """Their README describes a certificate hash; measured, it is the SPKI."""
    out = parse_tinfoil(_v3_doc())[0]
    assert out["tls_spki_fingerprint"] == "ab" * 32
    assert out["hpke_public_key"] == "cd" * 32


# --- device evidence --------------------------------------------------------


def test_empty_device_evidence_records_a_reason_not_a_verdict():
    out = parse_tinfoil(_v3_doc())[0]
    assert out["nvidia_evidence_count"] == "0"
    assert "empty" in out["gpu_evidence_reason"]


def test_gpu_count_is_left_unset_on_the_v3_document():
    """v3 carries no declared vm_shape, so the consistency gate must not be
    fed a fabricated zero. Unset reads as unverifiable, which is honest."""
    out = parse_tinfoil(_v3_doc())[0]
    assert out["gpu_count"] == ""


# --- the bare v2 document ---------------------------------------------------


def test_bare_v2_document_is_not_treated_as_having_evidence():
    doc = {
        "format": "https://tinfoil.sh/predicate/sev-snp-guest/v2",
        "body": base64.b64encode(gzip.compress(b"\x03" * 1184)).decode(),
    }
    out = parse_tinfoil(doc)[0]
    assert "no evidence set without a nonce" in out["note"]
    assert out.get("crypto_material_hash", "") == ""


def test_undecodable_body_is_reported_not_crashed():
    out = parse_tinfoil({"format": "x/v2", "body": "not-base64!!"}).pop()
    assert "not decodable" in out["note"]


def test_unexpected_payload_type_is_handled():
    assert parse_tinfoil("nonsense")[0]["note"] == "unexpected payload type"


# --- SNP TCB ----------------------------------------------------------------


def test_snp_tcb_is_not_read_from_guessed_offsets():
    """Regression: hand-rolled offsets returned 255.255.255.255 for a report
    whose real TCB is 10.0.23.84. A plausible-looking wrong number is exactly
    what a continuity log must not publish, so the engine parser is used."""
    from watch.sources import _snp_tcb_version

    # A real report cannot be fabricated offline, so assert the contract: a
    # short/garbage buffer yields "" rather than a fabricated dotted version.
    assert _snp_tcb_version(b"\x00" * 8) == ""
    assert _snp_tcb_version(b"") == ""
    assert _snp_tcb_version(b"\xff" * 1184) == ""


def test_gunzip_is_bounded_so_a_bomb_cannot_take_the_run_down():
    """gzip expands small input enormously and the body is a vendor's. Without a
    ceiling the whole expansion is read into memory at once."""
    import base64 as b64
    import gzip

    from watch.sources import MAX_DECOMPRESSED_BYTES, _gunzip_b64

    bomb = gzip.compress(b"\x00" * (4 * MAX_DECOMPRESSED_BYTES), 9)
    assert len(bomb) < MAX_DECOMPRESSED_BYTES            # it really is small
    out = _gunzip_b64(b64.b64encode(bomb).decode())
    assert len(out) == MAX_DECOMPRESSED_BYTES            # bounded, not 4x


def test_gunzip_leaves_small_bodies_intact():
    import base64 as b64
    import gzip

    from watch.sources import _gunzip_b64

    raw = b'{"items": []}'
    assert _gunzip_b64(b64.b64encode(gzip.compress(raw)).decode()) == raw
    assert _gunzip_b64(b64.b64encode(raw).decode()) == raw   # not gzipped
