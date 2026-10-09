"""The gate model: separately scored layers, with an honest confidence ladder."""
from watch.checks import (
    Checks,
    EvidenceStrength,
    GateStatus,
    gate_summary,
    score_gates,
)


def _gates(checks, record=None):
    return {g.name: g for g in score_gates(checks, record or {})}


def test_gates_are_scored_separately_not_collapsed():
    """Seven layers, each with its own outcome. A single verdict would hide
    which layer actually failed."""
    gates = score_gates(Checks(), {})
    assert len(gates) >= 7
    assert len({g.name for g in gates}) == len(gates)


def test_a_verified_quote_is_marked_verified_not_declared():
    gates = _gates(Checks(signature_valid="true"))
    assert gates["hardware"].status is GateStatus.GOOD
    assert gates["hardware"].strength is EvidenceStrength.VERIFIED


def test_an_unattempted_check_is_unverifiable_not_bad():
    """'' means we did not look. Mapping that to BAD would manufacture a
    finding out of a probe that never ran."""
    gates = _gates(Checks())
    assert gates["hardware"].status is GateStatus.UNVERIFIABLE


def test_a_failed_signature_is_bad():
    gates = _gates(Checks(signature_valid="false"))
    assert gates["hardware"].status is GateStatus.BAD


def test_workload_identity_cannot_be_concluded_without_an_expectation():
    """This log has no expected measurement to compare against, so it must
    report the gate as unverifiable rather than implying a pass."""
    gates = _gates(Checks(), {"measurement": "a" * 64})
    assert gates["workload identity"].status is GateStatus.UNVERIFIABLE


def test_vendor_naming_a_repo_is_declared_never_verified():
    """A repo URL in the payload is the vendor's statement about itself. We did
    not fetch and rebuild the image, so it cannot be verified."""
    gates = _gates(
        Checks(),
        {"repo_url": "https://github.com/x/y.git", "repo_commit": "abc123"},
    )
    gate = gates["source provenance"]
    assert gate.strength is EvidenceStrength.DECLARED
    assert gate.strength is not EvidenceStrength.VERIFIED


# --- GPU evidence consistency ----------------------------------------------
#
# This gate is NOT "is GPU evidence present". Two vendors declare zero GPUs and
# attach no GPU evidence, and that AGREES. A presence check would accuse both.


def test_zero_gpus_and_no_evidence_agree_and_are_good():
    gates = _gates(Checks(), {"gpu_count": "0", "nvidia_evidence_count": "0"})
    assert gates["GPU evidence consistency"].status is GateStatus.GOOD


def test_declared_gpus_with_no_evidence_is_the_bad_case():
    gates = _gates(Checks(), {"gpu_count": "3", "nvidia_evidence_count": "0"})
    assert gates["GPU evidence consistency"].status is GateStatus.BAD


def test_missing_declared_count_is_unverifiable_not_good():
    """Absence of the declared shape must not read as consent."""
    gates = _gates(Checks(), {"nvidia_evidence_count": "0"})
    assert gates["GPU evidence consistency"].status is GateStatus.UNVERIFIABLE


# --- TCB --------------------------------------------------------------------


def test_tcb_current_is_good_and_outdated_is_bad():
    assert _gates(Checks(tcb_status="current"))["TCB policy"].status is GateStatus.GOOD
    assert _gates(Checks(tcb_status="outdated"))["TCB policy"].status is GateStatus.BAD


def test_tcb_unknown_stays_unverifiable():
    assert _gates(Checks(tcb_status="unknown"))["TCB policy"].status is \
        GateStatus.UNVERIFIABLE


# --- summary ----------------------------------------------------------------


def test_gate_summary_counts_by_status():
    gates = score_gates(
        Checks(signature_valid="true", tls_group="X25519MLKEM768", tcb_status="current"),
        {"gpu_count": "0", "nvidia_evidence_count": "0"},
    )
    counts = gate_summary(gates)
    assert counts["good"] >= 3
    assert sum(counts.values()) == len(gates)


def test_strength_ladder_is_ordered_strongest_first():
    order = list(EvidenceStrength)
    assert order[0] is EvidenceStrength.VERIFIED
    assert order[1] is EvidenceStrength.CORROBORATED
    assert order.index(EvidenceStrength.DECLARED) > order.index(EvidenceStrength.CORROBORATED)
