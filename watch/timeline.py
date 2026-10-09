"""Analysis over the observation log.

This module holds everything that reads the log and answers questions about it:
what changed, how long a vendor's published evidence has been stable, which
fields count as identity. It has no opinion about how any of that is shown.

It replaced ``watch/render.py``, which mixed this analysis with a page
generator. The page is gone; the analysis is not. Callers decide the output.

The log is the interface. ``observations.jsonl`` is append-only, one JSON
object per observation, and the field names in it are the contract. Renaming a
field is a breaking change to anyone reading the log, so the names here are
deliberately explicit.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The fields whose change means the deployment changed. Deliberately excludes
#: ``raw_bytes`` and ``response_sha256``, which change whenever any byte of the
#: response moves, including fields we do not care about. The response hash is
#: recorded in the log for verification; it is not identity.
IDENTITY_FIELDS = (
    "measurement",
    # TCB is a security version number that moves on microcode and module
    # updates. It is the field CVEs map against, so a change here is the single
    # most consequential event this log can record.
    "tcb_version",
    "tcb_reference",
    "os_image_hash",
    "app_id",
    "mr_kms",
    "keyset_digest",
    "repo_commit",
    "cert_spki_sha256",
    "doc_format",
    "protocol",
    "protocol_commit",
    "release_id",
    "release_bundle",
    "workload_digests",
)

#: Readable names for the identity fields. A consumer rendering the log can use
#: these instead of inventing its own vocabulary for the same fields.
FIELD_LABELS = {
    "measurement": "measurement",
    "tcb_version": "TCB SVN",
    "tcb_reference": "TDX module",
    "os_image_hash": "OS image hash",
    "app_id": "app id",
    "mr_kms": "KMS measurement",
    "keyset_digest": "keyset digest",
    "repo_commit": "source commit",
    "cert_spki_sha256": "cert SPKI",
    "doc_format": "document format",
    "protocol": "attestation protocol",
    "protocol_commit": "protocol commit",
    "release_id": "release",
    "release_bundle": "release bundle",
    "workload_digests": "workload digests",
}

#: The date the unreadable-endpoint survey below was taken. A consumer printing
#: the list must print the date with it; an undated list of HTTP statuses ages
#: into a false claim.
UNREADABLE_DATE = "2026-10-09"

#: Providers checked on UNREADABLE_DATE that do not publish attestation evidence
#: an anonymous reader can verify. Each entry is an observation about publication
#: posture, with the exact response received. Not a judgement, and not a claim
#: that these providers do no verification -- several publish evidence through
#: their own authenticated tooling, which is a different thing from publishing
#: it openly.
#:
#: This is data, not a rendering of the log: these endpoints were probed once,
#: by hand, and no observation record exists for most of them. It lives here so
#: a consumer can show what the crawl cannot observe on its own.
UNREADABLE = (
    ("tinfoil", "api.tinfoil.sh/v1/attestation/report",
     "426", "rejects unencrypted bodies, requires an Encrypted-HTTP-Body-Protocol body"),
    ("near", "cloud-api.near.ai/v1/attestation/report", "401", "requires an API key"),
    ("chutes", "api.chutes.ai/v1/attestation", "429", "rate-limits anonymous reads"),
    ("venice", "api.venice.ai/api/v1/tee/attestation?model=", "400",
     "endpoint works and takes a model; 20 models tested, none TEE-capable, "
     "109 rate-limited and untested"),
    ("privatemode", "privatemode.ai/api/attestation", "404", "no public path"),
    ("maple", "api.maple.ai/attestation", "DNS", "host does not resolve"),
    ("nanogpt", "nano-gpt.com/api/attestation", "404", "no public path"),
    ("baseten", "api.baseten.co/attestation", "202", "returns HTML, not evidence"),
    ("confidentialai", "api.confidential.ai/attestation", "200", "readable with a nonce"),
    ("redpill", "api.redpill.ai/v1/attestation/report", "200", "readable and challengeable"),
    ("phala", "inference.phala.com/v1/aci/attestation", "200", "readable; ignores challenges"),
    ("ppq", "api.ppq.ai/attestation", "200", "readable"),
)


@dataclass
class Change:
    observed_at: str
    field: str
    before: str
    after: str


def load(path: Path) -> list[dict[str, Any]]:
    """Read the log, skipping lines that are not valid JSON.

    A partially written line is a corrupt line, not a reason to lose the rest of
    the history.
    """
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def by_vendor(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group observations by vendor, oldest first.

    ``__heartbeat__`` is a record about the crawl itself, not a vendor, so it is
    not grouped with them.
    """
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rec in records:
        if rec.get("vendor") == "__heartbeat__":
            continue
        groups[rec["vendor"]].append(rec)
    for rows in groups.values():
        rows.sort(key=lambda r: r.get("observed_at", ""))
    return dict(groups)


def find_changes(rows: list[dict[str, Any]]) -> list[Change]:
    """Changes in identity fields between consecutive *usable* observations.

    A field going from present to empty is not a change; it is a failed parse or
    a source that stopped publishing. Only a value moving from one non-empty
    value to another counts, so a bad week does not fabricate drift.
    """
    usable = [r for r in rows if r.get("http_status") == 200]
    changes: list[Change] = []
    for prev, cur in zip(usable, usable[1:]):
        for f in IDENTITY_FIELDS:
            a, b = prev.get(f, ""), cur.get(f, "")
            if a and b and a != b:
                changes.append(Change(cur["observed_at"], f, a, b))
    return changes


def stability(rows: list[dict[str, Any]]) -> tuple[str, int]:
    """(since, usable_count) -- the caller decides how to word it.

    Two observations is the minimum needed to say anything about stability. With
    one, the honest statement is that it has been observed once, not that it is
    unchanged. Reporting a single observation as "unchanged since <its own
    timestamp>" reads as a stability claim and is not one.
    """
    usable = [r for r in rows if r.get("http_status") == 200]
    if not usable:
        return "", 0
    changes = find_changes(usable)
    since = changes[-1].observed_at if changes else usable[0]["observed_at"]
    return since, len(usable)


def strip_query(url: str) -> str:
    """The endpoint without its per-run parameters.

    A request-bound source carries a fresh nonce each run, which is not part of
    the endpoint's identity and should not appear as though it were.
    """
    return url.split("?", 1)[0]
