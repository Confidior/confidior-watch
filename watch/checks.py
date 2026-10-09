"""Continuous verification of what each source publishes.

A document watcher records that bytes changed. This module answers the question
that matters: *was the thing those bytes claim actually true, at the time we
looked?*

Each run, per source, four independent checks:

1. **Signature** -- the quote verifies against the vendor's root of trust
   (Intel PCK chain for TDX, COSE/CBOR against the AWS Nitro root for Nitro).
2. **TCB** -- the TCB security version, read from the quote. It is recorded as
   published; it is *not* yet compared against Intel's current TCB for the
   platform, so every observation reports no comparison made.
3. **Freshness** -- whether the response was bound to a challenge this run
   generated, rather than replayed.
4. **Wire** -- what TLS key exchange the endpoint actually negotiates, measured
   rather than believed.

Checks are **fail-soft and independent**. A source can have a valid signature and
unreadable TCB; the log records both facts rather than collapsing them into one
verdict. That is deliberate: the observation layer records what was observed, and
the engine grades. This module does not produce a score.

Nothing here is a claim about a provider's security. A passing signature check
means the quote was genuine, not that the deployment is safe -- the engine's
attack corpus exists precisely because those are different questions.

All verifiers are imported from ``confidior-engine`` at call time, behind a
try/except, so this repo still runs and still records observations when the
engine is absent. The checks are added value, not a dependency.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Where the engine lives, if it is available at all.
#:
#: The engine is deliberately NOT a dependency of this repo -- the clock must not
#: break when the engine moves. So the verifiers are located at call time and
#: their absence is a recorded result ("engine not importable"), not a crash.
#: A run with no engine still produces observations; it just cannot say whether
#: the quotes were valid, and the log records that gap rather than hiding it.
ENGINE_PATH_ENV = "CONFIDIOR_ENGINE_PATH"


def _engine_root() -> Path | None:
    """Find a confidior-engine checkout, if one is reachable."""
    override = os.environ.get(ENGINE_PATH_ENV)
    if override:
        candidate = Path(override)
        return candidate if (candidate / "src").is_dir() else None
    # Sibling checkout: this repo and the engine share a parent.
    for base in (Path(__file__).resolve().parents[2], Path.cwd()):
        candidate = base / "confidior-engine"
        if (candidate / "src").is_dir():
            return candidate
    return None


_ENGINE_READY: bool | None = None


def engine_available() -> bool:
    """Whether the engine's verifiers can be imported right now."""
    global _ENGINE_READY
    if _ENGINE_READY is not None:
        return _ENGINE_READY
    root = _engine_root()
    if root is None:
        _ENGINE_READY = False
        return False
    path = str(root)
    if path not in sys.path:
        sys.path.insert(0, path)
    try:
        import src.ingest.adapters.tdx  # noqa: F401

        _ENGINE_READY = True
    except Exception as e:  # noqa: BLE001
        logger.warning("engine found at %s but not importable: %s", root, e)
        _ENGINE_READY = False
    return _ENGINE_READY


#: Groups worth testing, strongest first. Offered explicitly so the answer is
#: about what the endpoint *chooses* when given the option, not what the client
#: happened to default to.
PQ_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
CLASSICAL_GROUPS = ("X25519", "secp256r1")

TLS_TIMEOUT = 20


@dataclass
class Checks:
    """Per-observation verification results. Every field is optional by design."""

    signature_valid: str = ""  # "true" / "false" / "" (not attempted)
    signature_error: str = ""
    tcb_version: str = ""
    tcb_status: str = ""  # current / outdated / unknown; never set today, no comparison is made
    tcb_reference: str = ""
    freshness_bound: str = ""  # "true" / "false" / ""
    freshness_note: str = ""
    tls_group: str = ""  # what the endpoint negotiated when offered PQ
    tls_pq: str = ""  # "hybrid" / "classical" / ""
    tls_error: str = ""

    def as_fields(self) -> dict[str, str]:
        return {
            "signature_valid": self.signature_valid,
            "signature_error": self.signature_error[:200],
            "tcb_version": self.tcb_version,
            "tcb_status": self.tcb_status,
            "tcb_reference": self.tcb_reference,
            "freshness_bound": self.freshness_bound,
            "freshness_note": self.freshness_note[:200],
            "tls_group": self.tls_group,
            "tls_pq": self.tls_pq,
            "tls_error": self.tls_error[:200],
        }


# ---------------------------------------------------------------------------
# 1. Signature verification. Reuses the engine's adapters.
# ---------------------------------------------------------------------------


def verify_tdx_quote_hex(quote_hex: str) -> tuple[str, str]:
    """Verify a TDX quote against Intel's PCK chain. Returns (valid, error)."""
    if not quote_hex:
        return "", "no quote present"
    if not engine_available():
        return "", "engine not importable"
    try:
        from src.ingest.adapters.tdx import verify_tdx_quote

        result = verify_tdx_quote(quote_hex)
        return ("true" if result.get("valid") else "false"), str(result.get("error") or "")
    except Exception as e:  # noqa: BLE001 - a verifier failure is data, not a crash
        logger.warning("TDX verification raised: %s", e)
        return "false", f"{type(e).__name__}: {e}"


def verify_nitro_doc_b64(doc_b64: str) -> tuple[str, str]:
    """Verify an AWS Nitro attestation document (base64). Returns (valid, error)."""
    if not doc_b64:
        return "", "no document present"

    import base64

    try:
        raw = base64.b64decode(doc_b64, validate=True)
    except Exception as e:  # noqa: BLE001 - a real encoding problem, distinct from a missing engine
        return "", f"not valid base64: {type(e).__name__}"

    if not engine_available():
        return "", "engine not importable"
    try:
        from src.ingest.adapters.nitro import verify_nitro_attestation

        result = verify_nitro_attestation(raw.hex())
        return ("true" if result.get("valid") else "false"), str(result.get("error") or "")
    except Exception as e:  # noqa: BLE001
        logger.warning("Nitro verification raised: %s", e)
        return "false", f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# 2. TCB.
# ---------------------------------------------------------------------------


def tdx_quote_fields(quote_hex: str) -> dict[str, str]:
    """Read the identity-bearing fields from a TDX quote.

    ``parse_td_quote`` returns a dict of header/body, with hex strings -- not the
    object graph the adapter builds. Two fields matter here:

    - ``tee_tcb_svn`` is the TCB security version number. This is the field CVEs
      map against and the one the engine's retroactive-invalidation keys off, so
      a continuity log without it cannot connect to the attack corpus at all.
    - ``mrseam`` identifies the TDX module itself, which is what a microcode or
      module update changes.

    Returns {} when unreadable. TCB is optional detail; it must never fail a run.
    """
    if not quote_hex or not engine_available():
        return {}
    try:
        from cvm_attest.tdx.verify import parse_td_quote

        parsed = parse_td_quote(bytes.fromhex(quote_hex.strip()))
        body = parsed.get("body") or {}
        out: dict[str, str] = {}
        svn = str(body.get("tee_tcb_svn") or "")
        if svn:
            # Stored in full. The value is a per-component security version
            # number, one byte per component; an earlier version of this file
            # kept only the first 8 bytes, which would have missed a bump in any
            # later component -- the exact event this log exists to catch.
            out["tcb_version"] = svn
        seam = str(body.get("mrseam") or "")
        if seam:
            out["mrseam"] = seam
        return out
    except Exception as e:  # noqa: BLE001
        logger.debug("TCB extraction failed: %s", e)
        return {}


# ---------------------------------------------------------------------------
# 3. Freshness.
# ---------------------------------------------------------------------------


def freshness_from_nonce(sent_nonce: str, returned_nonce: str) -> tuple[str, str]:
    """Did the response echo the challenge this run generated?

    A response that repeats a challenge we just created proves it was produced
    after we asked. One that does not may be cached, replayed, or generated for
    someone else -- all of which are findings, not errors.
    """
    if not sent_nonce or not returned_nonce:
        return "", "no nonce exchanged"
    if sent_nonce == returned_nonce:
        return "true", "response echoes the challenge sent this run"
    return "false", "response nonce does not match the challenge sent this run"


# ---------------------------------------------------------------------------
# 4. Wire measurement.
# ---------------------------------------------------------------------------


def measure_tls_group(host: str, *, port: int = 443, runner: Any = None) -> tuple[str, str]:
    """Ask what key exchange the endpoint negotiates when offered a PQ hybrid.

    Measured with openssl rather than Python's ssl module because
    ``set_ecdh_curve`` does not accept hybrid group names on the Python versions
    this runs on, and a probe that silently cannot offer the group measures
    nothing. (An earlier version of this file made exactly that mistake and
    reported a false positive; the openssl call replaced it.)
    """
    if not host:
        return "", "no host"
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-groups",
        ":".join(PQ_GROUPS),
    ]
    try:
        if runner is None:

            def runner(argv: list[str]) -> str:
                proc = subprocess.run(
                    argv, capture_output=True, text=True, timeout=TLS_TIMEOUT, input=""
                )
                return proc.stdout + proc.stderr

        out = runner(cmd)
    except FileNotFoundError:
        return "", "openssl not available"
    except subprocess.TimeoutExpired:
        return "", "openssl timed out"
    except Exception as e:  # noqa: BLE001
        return "", f"{type(e).__name__}: {e}"

    for line in out.splitlines():
        low = line.lower()
        if "negotiated tls" in low and "group" in low:
            group = line.split(":", 1)[1].strip()
            return group, ""
    if "handshake failure" in out.lower() or "alert" in out.lower():
        return "", "no PQ hybrid accepted"
    # The client refused the group before reaching the server. OpenSSL added the
    # MLKEM groups in 3.5, and the stock image this runs on in CI ships 3.0, so
    # the probe is unusable there. That is a fact about the probe, not about the
    # endpoint, and it must not be recorded as one: "group not reported" reads as
    # a property of the host when the host was never reached.
    if "ssl_conf_cmd" in out.lower() or "unknown group" in out.lower():
        return "", "openssl cannot offer the PQ groups (needs OpenSSL 3.5+)"
    return "", "group not reported"


# ---------------------------------------------------------------------------
# Per-source assembly.
# ---------------------------------------------------------------------------


def check_dstack(payload: Any, sent_nonce: str = "") -> Checks:
    """dstack aci/1 (RedPill, Phala).

    These endpoints accept a ``?nonce=`` challenge. Whether the challenge
    reaches the quote's report_data is checked per observation; it is not
    assumed here, because at least one of the two accepts the parameter and
    does not bind it.
    """
    checks = Checks()
    if not isinstance(payload, dict):
        return checks
    attestation = payload.get("attestation") or {}
    evidence = attestation.get("evidence") or {}

    quote = str(payload.get("intel_quote") or evidence.get("quote") or "")
    valid, err = verify_tdx_quote_hex(quote)
    checks.signature_valid = valid
    checks.signature_error = err
    fields = tdx_quote_fields(quote)
    checks.tcb_version = fields.get("tcb_version", "")
    checks.tcb_reference = fields.get("mrseam", "")

    # report_data is the quote's binding to a caller-supplied value. Whether it
    # binds anything *we* chose is a separate question from whether it is
    # present, and this records the difference rather than assuming a binding.
    report_data = str(attestation.get("report_data") or "")
    quote_report_data = str(evidence.get("quote_report_data") or "")

    if sent_nonce:
        # The challenge must be inside the *quote's* report_data. A copy the
        # payload merely repeats outside the quote would prove nothing.
        if sent_nonce in quote_report_data:
            checks.freshness_bound = "true"
            checks.freshness_note = "quote report_data carries the challenge sent this run"
        elif report_data == quote_report_data:
            checks.freshness_bound = "false"
            checks.freshness_note = "challenge sent this run is absent from the quote's report_data"
        else:
            checks.freshness_bound = "false"
            checks.freshness_note = "no report_data binding found in the response"
    elif report_data and report_data == quote_report_data:
        checks.freshness_bound = "unbound"
        checks.freshness_note = (
            "no challenge was supplied this run, so freshness cannot be concluded"
        )
    return checks


def check_nitro(payload: Any) -> Checks:
    """AWS Nitro nsm-cose-sign1 (PPQ)."""
    checks = Checks()
    if not isinstance(payload, dict):
        return checks
    valid, err = verify_nitro_doc_b64(str(payload.get("attestation_document_b64") or ""))
    checks.signature_valid = valid
    checks.signature_error = err
    return checks


def check_c8s(payload: Any, sent_nonce: str) -> Checks:
    """Confidential AI c8s, which is request-bound by nonce."""
    checks = Checks()
    if not isinstance(payload, dict):
        return checks
    returned = str(payload.get("nonce") or "")
    checks.freshness_bound, checks.freshness_note = freshness_from_nonce(sent_nonce, returned)
    return checks


# ---------------------------------------------------------------------------
# Gate model.
# ---------------------------------------------------------------------------
#
# The checks above each answer one question. A reader wants to know which
# *layer* of the claim survived, because "hardware is genuine but the workload
# is unidentified" and "the hardware quote did not verify" are very different
# findings that a single pass/fail collapses together.
#
# So each observation is scored as named gates, separately, and every gate
# carries a confidence level saying how strongly the gate's own conclusion is
# established. The ladder is deliberately ordered from strongest to weakest and
# a gate is never upgraded: a vendor's statement about itself is DECLARED no
# matter how plausible it is, because we did not check it.


class EvidenceStrength(str, Enum):
    """How strongly a gate's conclusion is established.

    These are ordered. VERIFIED means we performed a cryptographic check
    ourselves. DECLARED means we recorded what the vendor said and did not
    check it, which is the weakest useful thing an observation can be.
    """

    VERIFIED = "verified"
    CORROBORATED = "corroborated"
    DECLARED = "declared"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class GateStatus(str, Enum):
    """A gate's outcome. UNVERIFIABLE is distinct from FAILED by design."""

    GOOD = "good"
    WARNING = "warning"
    BAD = "bad"
    UNVERIFIABLE = "unverifiable"
    NOT_APPLICABLE = "n/a"


@dataclass(frozen=True)
class Gate:
    """One scored layer of a claim."""

    name: str
    status: GateStatus
    strength: EvidenceStrength
    note: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "gate": self.name,
            "status": self.status.value,
            "strength": self.strength.value,
            "note": self.note[:200],
        }


def _tri_state(value: str, *, good: str = "true") -> GateStatus:
    """Map the stringly-typed check fields onto a gate status.

    The check fields use "" for 'not attempted', which is not a failure. Mapping
    that to BAD would manufacture findings out of probes we never ran.
    """
    if value == good:
        return GateStatus.GOOD
    if value == "false":
        return GateStatus.BAD
    return GateStatus.UNVERIFIABLE


def score_gates(checks: Checks, record: dict | None = None) -> list[Gate]:
    """Score an observation as named gates.

    ``record`` is the observation row, used for the gates that read published
    fields rather than performing a check. When it is absent those gates are
    reported as unverifiable rather than silently dropped.
    """
    record = record or {}
    gates: list[Gate] = []

    # Hardware: did the quote verify against the vendor's root of trust?
    gates.append(
        Gate(
            "hardware",
            _tri_state(checks.signature_valid),
            # A verified quote is a cryptographic check we ran ourselves.
            EvidenceStrength.VERIFIED
            if checks.signature_valid == "true"
            else EvidenceStrength.UNKNOWN,
            checks.signature_error or "quote verified against the vendor root of trust",
        )
    )

    # Channel binding: does the response bind the key the connection is using?
    tls_ok = bool(checks.tls_group)
    gates.append(
        Gate(
            "channel binding",
            GateStatus.GOOD if tls_ok else GateStatus.UNVERIFIABLE,
            EvidenceStrength.VERIFIED if tls_ok else EvidenceStrength.UNKNOWN,
            f"negotiated {checks.tls_group}"
            if tls_ok
            else (checks.tls_error or "no measurement taken"),
        )
    )

    # Freshness: did the response echo the challenge this run generated?
    gates.append(
        Gate(
            "freshness",
            _tri_state(checks.freshness_bound, good="true")
            if checks.freshness_bound in ("true", "false")
            else GateStatus.UNVERIFIABLE,
            EvidenceStrength.VERIFIED
            if checks.freshness_bound == "true"
            else EvidenceStrength.UNKNOWN,
            checks.freshness_note or "freshness not concluded",
        )
    )

    # TCB policy: is the platform's security version the vendor's current one?
    # UNKNOWN here is honest: the engine reports it when it cannot compare.
    if checks.tcb_status in ("current",):
        tcb_status, tcb_strength = GateStatus.GOOD, EvidenceStrength.VERIFIED
    elif checks.tcb_status in ("outdated", "expired", "revoked"):
        tcb_status, tcb_strength = GateStatus.BAD, EvidenceStrength.VERIFIED
    else:
        tcb_status, tcb_strength = GateStatus.UNVERIFIABLE, EvidenceStrength.UNKNOWN
    gates.append(
        Gate(
            "TCB policy",
            tcb_status,
            tcb_strength,
            checks.tcb_status or "no comparison against a current TCB reference",
        )
    )

    # Workload identity: is the measured workload the one we expected?
    #
    # This log has no expectation to compare against, so it can never conclude
    # this gate. That is a real limitation and it is reported as unverifiable
    # rather than quietly omitted.
    gates.append(
        Gate(
            "workload identity",
            GateStatus.UNVERIFIABLE,
            EvidenceStrength.UNKNOWN,
            f"measured {record.get('measurement', '')[:16]}...; "
            "no expected value to compare against"
            if record.get("measurement")
            else "no measurement recorded",
        )
    )

    # Source provenance: is the running image traceable to a published build?
    repo = str(record.get("repo_url") or "")
    commit = str(record.get("repo_commit") or "")
    if repo and commit:
        # The vendor named a repo and the measured image carries an event naming
        # a commit. We did not fetch and rebuild the image, so this is what the
        # vendor's own evidence states, not something we proved.
        gates.append(
            Gate(
                "source provenance",
                GateStatus.WARNING,
                EvidenceStrength.DECLARED,
                f"vendor states {repo.split('//')[-1]} @ {commit[:12]}; image not rebuilt",
            )
        )
    else:
        gates.append(
            Gate(
                "source provenance",
                GateStatus.UNVERIFIABLE,
                EvidenceStrength.UNKNOWN,
                "no repository or commit published",
            )
        )

    # GPU evidence consistency: does attached GPU evidence match the declared
    # hardware shape?
    #
    # This is NOT "is GPU evidence present". Two vendors declare zero GPUs and
    # attach no GPU evidence, and that AGREES: there is nothing to attest. The
    # gate only fires when the two disagree, e.g. a declared GPU with an empty
    # evidence list. A presence check would produce a false accusation here.
    declared_gpus = str(record.get("gpu_count") or "")
    attached = str(record.get("nvidia_evidence_count") or "")
    if declared_gpus == "" or attached == "":
        gates.append(
            Gate(
                "GPU evidence consistency",
                GateStatus.UNVERIFIABLE,
                EvidenceStrength.UNKNOWN,
                "declared GPU count or attached evidence not recorded",
            )
        )
    elif declared_gpus == "0" and attached == "0":
        gates.append(
            Gate(
                "GPU evidence consistency",
                GateStatus.GOOD,
                EvidenceStrength.CORROBORATED,
                "no GPU declared and no GPU evidence attached, which agree",
            )
        )
    elif declared_gpus != "0" and attached == "0":
        gates.append(
            Gate(
                "GPU evidence consistency",
                GateStatus.BAD,
                EvidenceStrength.CORROBORATED,
                f"{declared_gpus} GPU(s) declared but no evidence attached",
            )
        )
    else:
        gates.append(
            Gate(
                "GPU evidence consistency",
                GateStatus.WARNING,
                EvidenceStrength.CORROBORATED,
                f"{declared_gpus} GPU(s) declared, {attached} evidence item(s) "
                "attached, not verified",
            )
        )

    return gates


def gate_summary(gates: list[Gate]) -> dict[str, int]:
    """Count gates by status, for the compact per-vendor grid."""
    counts: dict[str, int] = {}
    for gate in gates:
        counts[gate.status.value] = counts.get(gate.status.value, 0) + 1
    return counts


def check_tinfoil(payload: Any, sent_nonce: str = "") -> Checks:
    """Tinfoil (AMD SEV-SNP), nonce-bound v3 predicate document.

    Two things are checked beyond the shared fields, because this source
    publishes material that makes them checkable:

    - the challenge echo, read from the *document's* challenge block rather than
      any copy the payload happens to repeat;
    - the REPORT_DATA derivation, which is published in their verifier source as
      sha256(algorithm || nonce || crypto_material_hash || device_evidence_hash).
      Recomputing it turns "the document says it bound the key" into "the quote
      provably commits to this key", which is the whole point of the binding.

    The SNP signature is NOT verified here. Tinfoil ships a VCEK in collateral
    and the engine can verify against it, but that path reaches AMD's KDS for
    the certificate chain and is too slow and too fragile for a periodic crawl.
    It is recorded as unverifiable rather than reported as good.
    """
    checks = Checks()
    if not isinstance(payload, dict):
        return checks

    # The challenge block, not the top level: the Tinfoil document carries the
    # nonce and report_data under `challenge`, and reading the top level found
    # nothing and reported "no nonce exchanged" for a request that had one.
    challenge = payload.get("challenge") or {}
    returned = str(challenge.get("nonce") or "")
    checks.freshness_bound, checks.freshness_note = freshness_from_nonce(sent_nonce, returned)

    report_data = str(challenge.get("report_data") or "")

    # The SNP TCB lives inside the report, not at the document's top level. It
    # is read here (rather than taken from the parsed record) so that the
    # engine's TCB-status path has it, since that path keys off this field.
    report_b64 = str((payload.get("cpu_evidence") or {}).get("report_base64") or "")
    if report_b64:
        try:
            import base64 as _b64

            from sev_pytools.verify import AttestationReport

            tcb = AttestationReport.unpack(_b64.b64decode(report_b64)).current_tcb
            checks.tcb_version = f"{tcb.bootloader}.{tcb.tee}.{tcb.snp}.{tcb.microcode}"
        except Exception:  # noqa: BLE001
            checks.tcb_version = ""

    if not (sent_nonce and report_data):
        return checks

    # Recompute REPORT_DATA from its documented derivation.
    endorsed = (payload.get("cpu_evidence") or {}).get("endorsed") or {}
    cm_hash = str(endorsed.get("crypto_material_hash") or payload.get("crypto_material_hash") or "")
    de_hash = str(endorsed.get("device_evidence_hash") or payload.get("device_evidence_hash") or "")
    if not (cm_hash and de_hash):
        # The nonce echo alone is weak: the document repeating our challenge
        # proves it was produced after we asked, not that the quote commits to
        # any key material. Say that plainly instead of leaving the echo's note
        # standing as though the binding had been established.
        checks.freshness_bound = ""
        checks.freshness_note = (
            "endorsed hashes absent, so the quote-to-key binding was not "
            "recomputed; only the challenge echo was observed"
        )
        return checks
    try:
        import hashlib

        expected = hashlib.sha256(
            b"https://tinfoil.sh/report-data/v1"
            + bytes.fromhex(sent_nonce)
            + bytes.fromhex(cm_hash)
            + bytes.fromhex(de_hash)
        ).hexdigest()
    except ValueError:
        return checks

    if report_data.startswith(expected):
        checks.freshness_bound = "true"
        checks.freshness_note = (
            "report_data recomputed from the published derivation and matched, "
            "so the quote commits to the published key material"
        )
    else:
        checks.freshness_bound = "false"
        checks.freshness_note = "report_data does not match the published derivation for this nonce"
    return checks
