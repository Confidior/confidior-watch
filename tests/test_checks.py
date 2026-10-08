"""Verification tests: signature, TCB, freshness, wire.

These exercise the *shape* of each check without network access. Live
verification is exercised by the collector's own runs; what is asserted here is
that a result is always produced, that "not attempted" stays distinguishable
from "false", and that no failure path raises.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from watch.checks import (  # noqa: E402
    Checks,
    check_c8s,
    check_dstack,
    check_nitro,
    freshness_from_nonce,
    measure_tls_group,
    tdx_quote_fields,
    verify_nitro_doc_b64,
    verify_tdx_quote_hex,
)

# --- the distinction that matters ------------------------------------------


def test_not_attempted_is_distinguishable_from_failed():
    """"" (not attempted) and "false" (failed) must never collapse.

    A missing engine means we could not check. A failed check means we checked
    and it failed. Recording the second when the first is true would be a false
    accusation, which is worse than no check at all.
    """
    c = Checks()
    assert c.signature_valid == ""
    assert c.signature_valid != "false"


def test_checks_fields_are_all_strings_and_bounded():
    c = Checks(signature_error="x" * 500)
    fields = c.as_fields()
    assert all(isinstance(v, str) for v in fields.values())
    assert len(fields["signature_error"]) <= 200


# --- signature --------------------------------------------------------------


def test_tdx_of_empty_quote_is_not_attempted():
    assert verify_tdx_quote_hex("") == ("", "no quote present")


def test_nitro_of_empty_document_is_not_attempted():
    assert verify_nitro_doc_b64("") == ("", "no document present")


def test_nitro_bad_base64_is_reported_as_an_encoding_error_not_a_bad_engine():
    """Attribution must be accurate: an encoding fault is not a missing engine."""
    valid, err = verify_nitro_doc_b64("!!!! not base64 !!!!")
    assert valid == ""
    assert "not valid base64" in err
    assert "engine" not in err


def test_verifiers_never_raise_on_garbage():
    for junk in ["", "zz", "00" * 10, "not-hex-at-all", "ff" * 5000]:
        assert isinstance(verify_tdx_quote_hex(junk), tuple)
        assert isinstance(verify_nitro_doc_b64(base64.b64encode(junk.encode()).decode()), tuple)


# --- TCB --------------------------------------------------------------------


def test_tcb_extraction_of_garbage_returns_empty_not_raises():
    assert tdx_quote_fields("") == {}
    assert tdx_quote_fields("zzzz") == {}


def test_tcb_is_recorded_separately_from_the_measurement():
    """TCB is the field CVEs map against. Without it the log cannot connect to
    the attack corpus, so it must be its own field and not folded into a digest."""
    c = Checks(tcb_version="0b01050000000000", tcb_reference="7bf063280e94")
    fields = c.as_fields()
    assert fields["tcb_version"] == "0b01050000000000"
    assert fields["tcb_reference"] == "7bf063280e94"
    assert "measurement" not in fields


# --- freshness --------------------------------------------------------------


def test_freshness_true_only_when_the_challenge_is_echoed():
    assert freshness_from_nonce("abc", "abc")[0] == "true"


def test_freshness_false_when_the_nonce_differs():
    """A response not bound to our challenge may be cached or replayed. That is
    a finding, and must be recorded as false rather than as unknown."""
    valid, note = freshness_from_nonce("abc", "xyz")
    assert valid == "false"
    assert "does not match" in note


def test_freshness_is_not_attempted_without_a_nonce():
    assert freshness_from_nonce("", "")[0] == ""
    assert freshness_from_nonce("abc", "")[0] == ""


def test_c8s_check_binds_to_the_nonce_this_run_sent():
    payload = {"nonce": "N1"}
    assert check_c8s(payload, "N1").freshness_bound == "true"
    assert check_c8s(payload, "N2").freshness_bound == "false"


def test_dstack_records_an_unbound_binding_as_unbound_not_as_fresh():
    """RedPill echoes report_data, but nothing we chose is in it. Calling that
    fresh would be exactly the overclaim this repo exists to avoid."""
    payload = {"attestation": {"report_data": "aa", "evidence": {"quote_report_data": "aa"}}}
    c = check_dstack(payload)
    assert c.freshness_bound == "unbound"
    assert "cannot be concluded" in c.freshness_note


def test_dstack_without_report_data_makes_no_freshness_claim():
    c = check_dstack({"attestation": {}})
    assert c.freshness_bound == ""


# --- wire -------------------------------------------------------------------


def test_tls_reports_hybrid_when_a_mlkem_group_is_negotiated():
    fake = lambda argv: "Negotiated TLS1.3 group: X25519MLKEM768\n"  # noqa: E731
    group, err = measure_tls_group("example.com", runner=fake)
    assert group == "X25519MLKEM768"
    assert err == ""


def test_tls_reports_classical_when_only_a_classical_group_is_negotiated():
    fake = lambda argv: "Negotiated TLS1.3 group: X25519\n"  # noqa: E731
    group, _ = measure_tls_group("example.com", runner=fake)
    assert group == "X25519"
    assert "MLKEM" not in group


def test_tls_offers_the_pq_groups_explicitly():
    """The measurement is about what the endpoint *chooses*, so the probe must
    offer the hybrid groups rather than accept a client default."""
    seen = {}

    def capture(argv):
        seen["argv"] = argv
        return "Negotiated TLS1.3 group: X25519MLKEM768\n"

    measure_tls_group("example.com", runner=capture)
    assert "-groups" in seen["argv"]
    joined = " ".join(seen["argv"])
    assert "X25519MLKEM768" in joined


def test_tls_handshake_failure_is_reported_not_guessed():
    fake = lambda argv: "sslv3 alert handshake failure\n"  # noqa: E731
    group, err = measure_tls_group("example.com", runner=fake)
    assert group == ""
    assert "PQ hybrid" in err or "not reported" in err


def test_tls_without_a_host_makes_no_claim():
    assert measure_tls_group("") == ("", "no host")


def test_tls_survives_a_runner_that_raises():
    def boom(argv):
        raise RuntimeError("no openssl")

    group, err = measure_tls_group("example.com", runner=boom)
    assert group == ""
    assert "no openssl" in err


# --- per-source assembly ----------------------------------------------------


def test_checks_survive_malformed_payloads():
    for bad in [None, [], "x", 0]:
        assert isinstance(check_dstack(bad), Checks)
        assert isinstance(check_nitro(bad), Checks)
        assert isinstance(check_c8s(bad, "n"), Checks)


# --- challenge binding (dstack) --------------------------------------------


def test_dstack_freshness_true_when_challenge_is_inside_the_quote():
    """The challenge must be in the *quote's* report_data. A copy the payload
    repeats outside the quote would prove nothing about the enclave."""
    payload = {"attestation": {"report_data": "N1", "evidence": {"quote_report_data": "xxN1xx"}}}
    c = check_dstack(payload, "N1")
    assert c.freshness_bound == "true"
    assert "quote report_data carries the challenge" in c.freshness_note


def test_dstack_freshness_false_when_the_endpoint_ignores_the_challenge():
    """Phala accepts ?nonce= and does not put it in the quote. That is worse
    than rejecting it, because it looks like it bound."""
    payload = {"attestation": {"report_data": "aa", "evidence": {"quote_report_data": "aa"}}}
    c = check_dstack(payload, "N1")
    assert c.freshness_bound == "false"
    assert "absent from the quote" in c.freshness_note


def test_dstack_challenge_outside_the_quote_is_not_accepted():
    """A binding that is present in the payload but not in the quote is not a
    binding: the payload is not what the hardware signed."""
    payload = {"attestation": {"report_data": "N1", "evidence": {"quote_report_data": "other"}}}
    assert check_dstack(payload, "N1").freshness_bound == "false"


def test_challenge_url_carries_a_distinct_nonce_each_rung():
    from watch.sources import challenge_url

    a, an = challenge_url("https://x/y")
    b, bn = challenge_url("https://x/y")
    assert a != b and an != bn
    assert f"nonce={an}" in a


def test_challengeable_sources_send_a_nonce():
    """RedPill and Phala are challengeable; verified by experiment, not assumed."""
    from watch.sources import default_sources

    for s in default_sources():
        if s.vendor in ("redpill", "phala", "confidentialai"):
            assert "nonce=" in s.url, f"{s.vendor} should send a challenge"
