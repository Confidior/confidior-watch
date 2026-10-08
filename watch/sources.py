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

- ``tinfoil`` -- ``api.tinfoil.sh/v1/attestation/report`` exists but rejects
  unencrypted bodies (HTTP 426, ``EHBP_REQUIRED``). Reading it would require
  implementing their client-side encryption. That is authentication in effect,
  and it would make this crawler a special-case client rather than a reader of
  public data.
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
    """A public evidence source: a vendor, a fetch, and a parse.

    ``parse`` receives the decoded response body and returns one or more partial
    observation dicts. The caller fills in vendor/url/status/hash.
    """

    vendor: str
    url: str
    parse: Callable[[Any], list[dict[str, Any]]]
    platform: str = ""
    note: str = ""


# --------------------------------------------------------------------------
# dstack / aci-1  (RedPill, Phala)
#
# Both endpoints return the same schema -- ``api_version: "aci/1"`` -- and on
# 2026-10-09 returned the *same* ``workload_keyset_digest``. RedPill's payload
# additionally embeds Phala domains and the dstack private-ai-gateway compose.
# That similarity is recorded here because it is evidence, not a bug in parsing.
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

    out = {
        "workload": "inference",
        "platform": "aws-nitro",
        "measurement": digest,
        "tcb_version": "",
        "doc_format": str(payload.get("format") or ""),
        "cert_spki_sha256": str(payload.get("cert_spki_sha256") or ""),
        "doc_bytes": str(size),
    }
    if not digest:
        out["note"] = "no attestation document in payload"
    return [out]


# --------------------------------------------------------------------------
# The v0 source set.
#
# Three sources, deliberately. See the internal strategy note section 6: five to eight
# with unbroken history proves continuity; sixty with patchy history proves
# nothing. Every addition costs adapter rot forever.
# --------------------------------------------------------------------------


def default_sources() -> list[Source]:
    return [
        Source(
            vendor="redpill",
            url="https://api.redpill.ai/v1/attestation/report",
            parse=parse_dstack,
            platform="intel-tdx",
        ),
        Source(
            vendor="phala",
            url="https://inference.phala.com/v1/aci/attestation",
            parse=parse_dstack,
            platform="intel-tdx",
        ),
        Source(
            vendor="ppq",
            url="https://api.ppq.ai/attestation",
            parse=parse_nsm_cose,
            platform="aws-nitro",
        ),
    ]
