"""Evidence sources, and the parsers that read them.

Every parser here was written against a response captured live on the date in
``VERIFIED``. None of them is written against documentation, because for these
endpoints there is none -- which is itself the finding this repo documents.

The rules that shaped this file:

- **A source that goes away is a finding, not a failure.** A dead endpoint
  produces an observation with its HTTP status. "No observations since DATE" is
  honest and interesting.
- **Choose sources that do not rot.** Public JSON, no authentication, no HTML.
- **Depth over breadth.** A small number with unbroken history proves continuity.
  A large number with patchy history proves nothing.
- **Never raise on a shape change.** A parser that cannot find its fields returns
  a note. An aborted run is a gap in the timeline and the timeline is the asset.

Deliberately excluded, with reasons recorded so nobody re-adds them by accident:

- ``tinfoil`` (the ``api.tinfoil.sh/v1/attestation/report`` path only) --
  that path exists but rejects unencrypted bodies (HTTP 426, ``EHBP_REQUIRED``).
  Reading it would require implementing their client-side encryption. That is
  authentication in effect, and it would make this crawler a special-case client
  rather than a reader of public data. Tinfoil *is* crawled, through its
  ``.well-known`` path, which serves its report without a client. See
  ``default_sources`` and ``parse_tinfoil`` below.
- ``near`` -- ``cloud-api.near.ai/v1/attestation/report`` returns 401. Keyed.
- ``chutes`` -- ``api.chutes.ai/v1/attestation`` returns 429 under plain GET;
  per-model evidence endpoints appear to need the provider's own flow.
- ``venice``, ``maple``, ``nanogpt``, ``privatemode`` -- no public attestation
  endpoint located at the obvious paths on 2026-10-09.

Each exclusion is a factual observation about publication posture, not a
judgement. Several of these providers may well publish evidence through their
own authenticated tooling; that is a different claim from publishing it openly.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

VERIFIED = "2026-10-09"


@dataclass(frozen=True)
class Source:
    """A public evidence source: a vendor, a fetch, a parse, and a checker.

    ``parse`` receives the decoded response body and returns one or more partial
    observation dicts. The caller fills in vendor/url/status/hash.

    ``check`` receives the same payload plus the nonce this run generated (empty
    for sources that are not request-bound) and returns verification results --
    signature, TCB, freshness. It is optional: a source with no checker still
    produces observations.
    """

    vendor: str
    url: str
    parse: Callable[[Any], list[dict[str, Any]]]
    platform: str = ""
    note: str = ""
    check: Callable[..., Any] | None = None
    host: str = ""


# --------------------------------------------------------------------------
# dstack / aci-1  (RedPill, Phala)
#
# Both endpoints return the same schema -- ``api_version: "aci/1"`` -- and on
# 2026-10-09 returned the *same* ``keyset_digest``, ``os_image_hash`` and
# ``tls_binding_domains``, and named the same dstack private-ai-gateway
# repository. That similarity is recorded here because it is evidence, not a
# bug in parsing.
# --------------------------------------------------------------------------


def _rt_mr3_events(attestation: dict[str, Any]) -> dict[str, str]:
    """Extract the named rt_mr3 events from a dstack TDX event log.

    These named events are the stable identity of the deployment: ``compose-hash``,
    ``os-image-hash``, ``app-id``, ``mr-kms``, ``key-provider``. They are what a
    continuity log should watch, because they are what changes when a vendor
    redeploys. ``instance-id`` is deliberately kept separate: it changes on every
    restart and is not identity.
    """
    evidence = attestation.get("evidence") or {}
    raw = evidence.get("event_log")
    if not raw:
        return {}
    try:
        events = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        return {}
    out: dict[str, str] = {}
    for event in events or []:
        name = event.get("event")
        if name and name not in out:
            out[name] = str(event.get("event_payload") or "")
    return out


def parse_dstack(payload: Any) -> list[dict[str, Any]]:
    """Parse a dstack ``aci/1`` attestation payload."""
    if not isinstance(payload, dict):
        return [{"note": "unexpected payload type"}]

    attestation = payload.get("attestation") or {}
    if not isinstance(attestation, dict):
        return [{"note": "attestation field is not an object"}]

    events = _rt_mr3_events(attestation)
    provenance = attestation.get("source_provenance") or {}
    keyset = attestation.get("workload_keyset") or {}

    caps = payload.get("service_capabilities") or {}

    # The declared hardware shape. This is what the GPU-evidence consistency
    # check compares attached evidence AGAINST: two vendors declare zero GPUs
    # and attach no GPU evidence, and that agrees. Only a mismatch is a finding.
    evidence = attestation.get("evidence") or {}
    vm_config = (
        payload.get("vm_config")
        or (evidence.get("vm_config") if isinstance(evidence, dict) else None)
        or {}
    )
    if isinstance(vm_config, str):
        try:
            vm_config = json.loads(vm_config)
        except json.JSONDecodeError:
            vm_config = {}
    gpu_count = ""
    if isinstance(vm_config, dict) and "num_gpus" in vm_config:
        gpu_count = str(vm_config.get("num_gpus"))
    receipt_keys = keyset.get("receipt_signing_keys") or []
    e2ee_keys = keyset.get("e2ee_public_keys") or []
    tls_keys = keyset.get("tls_public_keys") or []
    nvidia_raw = payload.get("nvidia_payload")
    nvidia: dict[str, Any] = {}
    if isinstance(nvidia_raw, str) and nvidia_raw:
        try:
            nvidia = json.loads(nvidia_raw)
        except json.JSONDecodeError:
            nvidia = {}

    out: list[dict[str, Any]] = [
        {
            "workload": "gateway",
            "platform": str(attestation.get("tee_type") or ""),
            "measurement": events.get("compose-hash", ""),
            "tcb_version": "",
            "keyset_digest": str(payload.get("workload_keyset_digest") or ""),
            "os_image_hash": events.get("os-image-hash", ""),
            "app_id": events.get("app-id", ""),
            "mr_kms": events.get("mr-kms", ""),
            "repo_commit": str(provenance.get("repo_commit") or ""),
            "repo_url": str(provenance.get("repo_url") or ""),
            "tee_type": str(attestation.get("tee_type") or ""),
            # --- declared capabilities ---
            "serving_role": str(caps.get("serving") or ""),
            "e2ee_versions": ",".join(caps.get("supported_e2ee_versions") or []),
            # --- key material published for verification ---
            "receipt_key_algos": ",".join(sorted({str(k.get("algo") or "") for k in receipt_keys})),
            "receipt_key_count": str(len(receipt_keys)),
            "e2ee_key_algos": ",".join(sorted({str(k.get("algo") or "") for k in e2ee_keys})),
            "e2ee_key_count": str(len(e2ee_keys)),
            "tls_binding_count": str(len(tls_keys)),
            "tls_binding_domains": ",".join(sorted({str(k.get("domain") or "") for k in tls_keys})),
            # --- custody and GPU ---
            "key_custody_provider": str(
                (attestation.get("key_custody") or {}).get("provider") or ""
            ),
            "gpu_count": gpu_count,
            "nvidia_arch": str(nvidia.get("arch") or ""),
            "nvidia_evidence_count": str(len(nvidia.get("evidence_list") or [])),
            # --- provenance of the source tree ---
            "provenance_image_digest": str(provenance.get("image_digest") or ""),
            "provenance_image": str(provenance.get("image_provenance") or ""),
            # --- the measured boot event names present ---
            "event_names": ",".join(sorted(events.keys())),
        }
    ]

    # Keyset expiry tracks rotation of the receipt/e2ee keys.
    not_after = keyset.get("not_after")
    if not_after:
        out[0]["keyset_not_after"] = str(not_after)

    # A note is recorded when a parse succeeds structurally but finds no
    # identity, so the timeline shows a source that returned data we could not
    # read rather than silently recording blanks.
    if not out[0]["measurement"] and not out[0]["keyset_digest"]:
        out[0]["note"] = "no identity field located in payload"
    return out


# --------------------------------------------------------------------------
# AWS Nitro NSM COSE (PPQ)
# --------------------------------------------------------------------------


def _spki_der_bytes(value: Any) -> bytes:
    """Decode the endpoint's base64 SPKI into DER bytes, or b"" if it is absent.

    The endpoint publishes ``cert_spki_der`` base64-encoded. The record field is
    named for DER *bytes*, so the length it reports must be the decoded length,
    not the length of the base64 string.
    """
    if not value:
        return b""
    try:
        return base64.b64decode(str(value), validate=True)
    except (binascii.Error, ValueError):
        return b""


def parse_nsm_cose(payload: Any) -> list[dict[str, Any]]:
    """Parse a ``nsm-cose-sign1`` attestation document wrapper.

    The document itself is CBOR/COSE and its contents are opaque here -- this
    crawler records *what the vendor published and when it changed*, and
    decoding the COSE structure belongs to the grading engine, not to the clock.
    What is recorded is the document's hash, its length, and the certificate
    SPKI, all of which change together when the deployment changes.
    """
    if not isinstance(payload, dict):
        return [{"note": "unexpected payload type"}]

    doc_b64 = str(payload.get("attestation_document_b64") or "")
    digest = ""
    size = 0
    if doc_b64:
        try:
            raw = base64.b64decode(doc_b64, validate=True)
            size = len(raw)
            import hashlib

            digest = hashlib.sha256(raw).hexdigest()
        except (binascii.Error, ValueError):
            return [{"note": "attestation_document_b64 is not valid base64"}]

    spki_der = _spki_der_bytes(payload.get("cert_spki_der"))
    out = {
        "workload": "inference",
        "platform": "aws-nitro",
        "measurement": digest,
        "tcb_version": "",
        "doc_format": str(payload.get("format") or ""),
        "cert_spki_sha256": str(payload.get("cert_spki_sha256") or ""),
        "doc_bytes": str(size),
        "hpke_key_present": "yes" if payload.get("hpke_public_key") else "no",
        # The field counts DER **bytes**, so the base64 the endpoint publishes has
        # to be decoded first. It previously ran len() over the encoded string,
        # which reported the base64 length: the PPQ record read 124 for a
        # certificate whose DER is 91 bytes, the length of a P-256 SPKI. It also
        # meant a certificate whose key changed but whose encoding kept the same
        # length would not register, and the log would report no change.
        "cert_spki_der_bytes": str(len(spki_der)) if spki_der else "",
    }
    if not digest:
        out["note"] = "no attestation document in payload"
    return [out]


# --------------------------------------------------------------------------
# Confidential AI (c8s)
#
# Request-bound: the response is generated against a nonce you supply, which is
# what makes freshness checkable rather than assumed. A base64url nonce of 43
# characters satisfies it; anything else is rejected as ``invalid_nonce``.
#
# This is the deepest source in the set. It publishes a measured container
# allowlist -- per-workload image digests, one per component of the serving
# stack -- plus a release bundle, an attestation protocol identifier and its
# commit, and a mesh CA hash. That is enough to see *which component* changed,
# not merely that something did.
#
# Note the honesty in the payload itself, which is worth preserving rather than
# papering over: ``scope`` reads ``launch-or-admission-only``, ``gpuEvidence``
# carries an empty list and a reason string, and the ``tls`` binding reports
# ``requires-attest-lb``. The vendor is being explicit about what this response
# does *not* prove. A continuity log should store those self-described limits,
# because a change in them is as interesting as a change in a digest.
# --------------------------------------------------------------------------


def parse_c8s(payload: Any) -> list[dict[str, Any]]:
    """Parse the c8s attestation response."""
    if not isinstance(payload, dict):
        return [{"note": "unexpected payload type"}]

    c8s = payload.get("c8s") or {}
    allowlist = (c8s.get("activeAllowlist") or {}).get("document") or {}
    workloads = allowlist.get("workloads") or {}

    # Hash the workload allowlist rather than storing all of it. The individual
    # digests are recorded in ``workload_digests`` for a readable diff; the hash
    # is what answers "did the measured stack change" in one value.
    import hashlib

    canonical = json.dumps(workloads, sort_keys=True, separators=(",", ":")).encode()
    allowlist_hash = hashlib.sha256(canonical).hexdigest()

    per_workload = {
        name: str(((w.get("containers") or [{}])[0]).get("digest") or "")
        for name, w in workloads.items()
        if isinstance(w, dict)
    }

    release = payload.get("release") or {}
    tls_block = payload.get("tls") or {}
    gpu = payload.get("gpuEvidence") or {}

    out: dict[str, Any] = {
        "workload": "inference-stack",
        "platform": "confidential-ai-c8s",
        "measurement": allowlist_hash,
        "cert_spki_sha256": str(c8s.get("meshCaSha256") or ""),
        "protocol": str(c8s.get("attestationProtocol") or ""),
        "protocol_commit": str(c8s.get("attestationProtocolC8sCommit") or ""),
        "release_id": str(release.get("id") or ""),
        "release_bundle": str(release.get("bundleSha256") or ""),
        "workload_count": str(len(workloads)),
        # Self-described limits. Stored because a change here is a change in
        # what the evidence claims to cover.
        "scope": str(payload.get("scope") or ""),
        "operational_status": str(payload.get("operationalStatus") or ""),
        "tls_binding_status": str((tls_block.get("binding") or {}).get("status") or ""),
        "gpu_evidence_count": str(len(gpu.get("evidence") or [])) if isinstance(gpu, dict) else "0",
        "gpu_evidence_reason": str(gpu.get("reason") or "") if isinstance(gpu, dict) else "",
        "frontdoor_mode": str(
            (payload.get("frontDoor") or {}).get("receipt", {}).get("front_door_mode") or ""
        ),
        "frontdoor_platform": str(
            (payload.get("frontDoor") or {}).get("receipt", {}).get("platform") or ""
        ),
        "serving_leaf_sha256": str(
            (payload.get("frontDoor") or {}).get("receipt", {}).get("serving_leaf_sha256") or ""
        ),
        "receipt_count": str(len(payload.get("receipts") or [])),
        "mesh_ca": str(c8s.get("meshCaSha256") or ""),
        "operator_key_status": str(
            (c8s.get("operatorTrust") or {}).get("activeKeySetStatus") or ""
        ),
        "operator_keyset_sha256": str(
            (c8s.get("operatorTrust") or {}).get("expectedKeySetSha256") or ""
        ),
        "schema_version": str(payload.get("schemaVersion") or ""),
        "nonce": str(payload.get("nonce") or ""),
        "workload_digests": json.dumps(per_workload, sort_keys=True, separators=(",", ":")),
    }
    if not workloads:
        out["note"] = "no workloads in allowlist"
    return [out]


# --------------------------------------------------------------------------
# The v1 source set.
#
# Five sources, deliberately. Five to eight with unbroken history proves
# continuity; sixty with patchy history proves nothing. Every addition costs
# adapter rot forever.
# --------------------------------------------------------------------------


def make_nonce() -> str:
    """A fresh challenge for a request-bound source."""
    import base64
    import os

    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def fresh_nonce() -> str:
    """A hex challenge for a source that accepts one in its query string."""
    import hashlib
    import os

    return hashlib.sha256(os.urandom(16)).hexdigest()


def challenge_url(base: str) -> tuple[str, str]:
    """(url, nonce) for a source that binds a caller-supplied challenge.

    Verified by experiment, not documentation: RedPill's report endpoint echoes
    ``?nonce=`` back inside the quote's report_data, which is what makes
    freshness checkable at all. An earlier version of this file assumed the
    dstack sources were not challengeable and recorded "not attempted" as though
    that were a property of the source rather than of the request.
    """
    nonce = fresh_nonce()
    return f"{base}?nonce={nonce}", nonce


def c8s_url() -> tuple[str, str]:
    """(url, nonce) for a request-bound source. The nonce is returned so the
    checker can confirm the response was bound to *this* run."""
    nonce = make_nonce()
    return f"https://api.confidential.ai/attestation?nonce={nonce}", nonce


def default_sources() -> list[Source]:
    from watch.checks import check_c8s, check_dstack, check_nitro, check_tinfoil

    return [
        Source(
            vendor="redpill",
            url=challenge_url("https://api.redpill.ai/v1/attestation/report")[0],
            parse=parse_dstack,
            platform="intel-tdx",
            check=check_dstack,
            host="api.redpill.ai",
        ),
        Source(
            vendor="phala",
            url=challenge_url("https://inference.phala.com/v1/aci/attestation")[0],
            parse=parse_dstack,
            platform="intel-tdx",
            check=check_dstack,
            host="inference.phala.com",
        ),
        Source(
            vendor="ppq",
            url="https://api.ppq.ai/attestation",
            parse=parse_nsm_cose,
            platform="aws-nitro",
            check=check_nitro,
            host="api.ppq.ai",
        ),
        Source(
            vendor="tinfoil",
            url=tinfoil_url()[0],
            parse=parse_tinfoil,
            platform="amd-sev-snp",
            check=check_tinfoil,
            host="inference.tinfoil.sh",
            note=(
                "AMD SEV-SNP. The bare endpoint returns a small v2 document; a "
                "64-hex nonce switches it to the v3 evidence set. Not to be "
                "confused with /v1/attestation, which needs an API key."
            ),
        ),
        Source(
            vendor="confidentialai",
            url=c8s_url()[0],
            parse=parse_c8s,
            platform="confidential-ai-c8s",
            check=check_c8s,
            host="api.confidential.ai",
        ),
    ]


# --------------------------------------------------------------------------
# Tinfoil (AMD SEV-SNP, self-describing predicate document)
#
# Tinfoil publishes at /.well-known/tinfoil-attestation on the *inference* host
# (tinfoil.sh itself returns 404). The response is a small JSON envelope whose
# `body` is gzipped base64. The bare document carries predicate sev-snp-guest/v2
# and, once a 32-byte hex nonce is supplied, switches to predicate
# attestation/v3 and returns the full evidence set.
#
# Reverse-engineered by experiment on 2026-10-09, not from documentation. Two
# things worth recording because they are easy to get wrong:
#
# 1. The v3 report_data does NOT simply hold a hash of the TLS certificate.
#    It is sha256("https://tinfoil.sh/report-data/v1" || nonce || crypto_material
#    _hash || device_evidence_hash), per the verifier source. Those hashes are
#    carried in cpu_evidence.endorsed, so the binding chain is quote -> endorsed
#    hashes -> crypto_material -> the TLS key. Verified byte-exact.
# 2. Their README describes the TLS binding as a certificate hash. Measured, it
#    is the SPKI hash. Small divergence, worth not repeating.
#
# No attestation is *published* on the release assets: the hardware-measurements
# .json named in an earlier draft has never existed (404 at both the pinned and
# latest paths). The live endpoint below is what the crawl reads.

TINFOIL_ATTESTATION_URL = "https://inference.tinfoil.sh/.well-known/tinfoil-attestation"
TINFOIL_REPORT_DATA_ALG = "https://tinfoil.sh/report-data/v1"


def tinfoil_url() -> tuple[str, str]:
    """(url, nonce) for Tinfoil. Requires a 64-hex challenge; a short one 400s,
    and the bare endpoint answers with a smaller document that carries no
    evidence set."""
    nonce = fresh_nonce()
    return f"{TINFOIL_ATTESTATION_URL}?nonce={nonce}", nonce


def _gunzip_b64(value: str) -> bytes:
    """Decode the base64+gzip envelope Tinfoil uses for evidence bodies."""
    import base64 as _b64
    import gzip as _gzip
    import io as _io

    raw = _b64.b64decode(value)
    if raw[:2] == b"\x1f\x8b":
        return _gzip.GzipFile(fileobj=_io.BytesIO(raw)).read()
    return raw


def parse_tinfoil(payload: Any) -> list[dict[str, Any]]:
    """Parse a Tinfoil attestation document.

    Handles both predicates: the bare v2 document (a raw SNP report) and the
    nonce-bound v3 document (challenge, cpu evidence, crypto material, device
    evidence). The v2 path keeps only what a bare report can say, rather than
    inventing fields the document does not carry.
    """
    if not isinstance(payload, dict):
        return [{"note": "unexpected payload type"}]

    fmt = str(payload.get("format") or "")
    out: dict[str, Any] = {"workload": "inference", "platform": "amd-sev-snp"}

    if fmt.endswith("attestation/v3"):
        cpu = payload.get("cpu_evidence") or {}
        endorsed = cpu.get("endorsed") or {}
        challenge = payload.get("challenge") or {}
        report_b64 = str(cpu.get("report_base64") or "")

        measurement = ""
        if report_b64:
            import base64 as _b64

            try:
                raw = _b64.b64decode(report_b64)
                # SNP report layout: measurement at 0x90, report_data at 0x50.
                if len(raw) >= 192:
                    measurement = raw[0x90:0xD0].hex()
                    out["snp_report_data"] = raw[0x50:0x90].hex()
                    out["snp_tcb"] = _snp_tcb_version(raw)
            except Exception:  # noqa: BLE001
                pass
        out["measurement"] = measurement

        # The nonce the service returned, and the report_data it committed to.
        out["nonce"] = str(challenge.get("nonce") or "")
        out["report_data"] = str(challenge.get("report_data") or "")

        # Endorsement hashes bind the quote to the crypto material and device
        # evidence sections. Recording them is what makes the binding chain
        # checkable later instead of taken on faith.
        out["crypto_material_hash"] = str(endorsed.get("crypto_material_hash") or "")
        out["device_evidence_hash"] = str(endorsed.get("device_evidence_hash") or "")

        # Crypto material: the TLS SPKI fingerprint and the HPKE public key.
        cm_raw = payload.get("crypto_material")
        if isinstance(cm_raw, str) and cm_raw:
            try:
                cm = (
                    json.loads(_gunzip_b64(cm_raw))
                    if not cm_raw.startswith("{")
                    else json.loads(cm_raw)
                )
                for item in cm.get("items") or []:
                    if item.get("id") == "tls":
                        out["tls_spki_fingerprint"] = str(item.get("data") or "")
                    elif item.get("id") == "hpke":
                        out["hpke_public_key"] = str(item.get("data") or "")
                out["tls_binding_count"] = str(len(cm.get("items") or []))
            except Exception:  # noqa: BLE001
                pass

        # Device evidence. Empty is a fact about the declaration, not a defect
        # on its own: this is compared against the declared GPU count.
        de_raw = payload.get("device_evidence")
        count = ""
        if isinstance(de_raw, str) and de_raw:
            try:
                de = (
                    json.loads(_gunzip_b64(de_raw))
                    if not de_raw.startswith("{")
                    else json.loads(de_raw)
                )
                items = de.get("items") or []
                count = str(len(items))
                out["gpu_evidence_reason"] = (
                    "" if items else "the document's device_evidence set is empty"
                )
            except Exception:  # noqa: BLE001
                pass
        out["nvidia_evidence_count"] = count
        out["gpu_count"] = ""  # v3 carries no declared vm_shape; left unset

        # Collateral: a VCEK is shipped inline, which is what allows the report
        # to be verified without reaching AMD's KDS.
        col = payload.get("collateral")
        if isinstance(col, list):
            out["collateral_count"] = str(len(col))
            for entry in col:
                data = entry.get("data") or {}
                if isinstance(data, dict) and data.get("vcek_der_base64"):
                    out["vcek_present"] = "true"
                    break

        out["device_evidence_format"] = ""
        return [out]

    # Bare v2: a raw gzipped SNP report with no wrapper fields.
    body = payload.get("body")
    if not isinstance(body, str) or not body:
        return [{"note": "no body in document"}]
    try:
        raw = _gunzip_b64(body)
    except Exception as e:  # noqa: BLE001
        return [{"note": f"body not decodable: {type(e).__name__}"}]
    if len(raw) >= 192:
        out["measurement"] = raw[0x90:0xD0].hex()
        out["snp_report_data"] = raw[0x50:0x90].hex()
        out["snp_tcb"] = _snp_tcb_version(raw)
    out["note"] = "bare v2 report: no evidence set without a nonce"
    return [out]


def _snp_tcb_version(raw: bytes) -> str:
    """The SNP reported TCB as dotted components.

    Uses the engine's parser rather than hand-rolled offsets. An earlier version
    of this function guessed the byte layout and returned 255.255.255.255 for a
    report whose real TCB is 10.0.23.84: plausible-looking, entirely wrong, and
    exactly the failure mode a continuity log must not have. Unpacking the
    struct properly is the only safe way to read it.
    """
    try:
        from sev_pytools.verify import AttestationReport

        report = AttestationReport.unpack(raw)
    except Exception:  # noqa: BLE001
        return ""

    # The engine's unpacker is happy to decode all-0xFF filler into
    # 255.255.255.255, so the result is sanity-checked rather than trusted.
    # A fabricated TCB is worse than none: it is the field CVEs map against.
    if getattr(report, "version", None) not in (2, 3):
        return ""
    try:
        tcb = report.current_tcb
        parts = (tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode)
    except AttributeError:
        return ""
    if any(not isinstance(p, int) or p < 0 or p > 255 for p in parts):
        return ""
    if parts == (255, 255, 255, 255) or parts == (0, 0, 0, 0):
        return ""
    return ".".join(str(p) for p in parts)
