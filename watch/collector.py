"""confidior-watch: a continuity log for published attestation evidence.

A scheduled crawl that records what vendors publish about their own attestation
evidence, over time, so that point-in-time observations become a time series.

A single capture is an anecdote. A thousand captures is a history. This is the
mechanism that turns one into the other.

What it is not: a service, a dashboard, a grader. It observes; it does not
grade. There is no uptime promise and no account. Its worst failure is a gap in
a timeline, and for an evidence archive silence never reads as a claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from watch.clock import utc_now_iso
from watch.sources import Source, default_sources

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 25.0
USER_AGENT = "confidior-watch/0.1 (+https://github.com/confidior/confidior-watch)"

#: Version of the log's own record shape.
#:
#: This is the *log's* version, not any vendor's. It is deliberately not called
#: ``schema_version``: that name is already a field in the record, where it
#: carries the version string the *vendor's* payload declares about itself.
#: Overloading it would make a consumer unable to tell which of the two it was
#: reading.
#:
#: Bump this when a field is renamed, removed, or changes meaning, because that
#: is what breaks a consumer. Adding an optional field does not bump it: an old
#: consumer ignoring an unknown key still reads the record correctly, and every
#: field is written on every line, so nothing becomes conditionally absent.
#:
#: A record without this key predates the envelope. Those lines are the original
#: field set and are compatible with version "1"; the envelope was added so the
#: *next* change can be detected at all.
LOG_SCHEMA = "1"

#: Every field written to the log. Kept explicit so the log is self-describing
#: and a reader never has to infer the schema from examples.
RECORD_FIELDS = (
    "log_schema",
    "observed_at",
    "vendor",
    "workload",
    "platform",
    "measurement",
    "tcb_version",
    "source_url",
    "http_status",
    "response_sha256",
    "raw_bytes",
    "keyset_digest",
    "os_image_hash",
    "app_id",
    "mr_kms",
    "repo_commit",
    "repo_url",
    "tee_type",
    "keyset_not_after",
    "doc_format",
    "cert_spki_sha256",
    "doc_bytes",
    "note",
    "protocol",
    "protocol_commit",
    "release_id",
    "release_bundle",
    "workload_count",
    "scope",
    "operational_status",
    "tls_binding_status",
    "gpu_evidence_count",
    "nonce",
    "workload_digests",
    # verification results (see watch/checks.py)
    "signature_valid",
    "signature_error",
    "tcb_status",
    "tcb_reference",
    "freshness_bound",
    "freshness_note",
    "tls_group",
    "tls_pq",
    "tls_error",
    # declared capability surface (what the provider says it offers)
    "serving_role",
    "e2ee_versions",
    "receipt_key_algos",
    "receipt_key_count",
    "e2ee_key_algos",
    "e2ee_key_count",
    "tls_binding_count",
    "tls_binding_domains",
    "key_custody_provider",
    "gpu_count",
    "nvidia_arch",
    "nvidia_evidence_count",
    "provenance_image_digest",
    "provenance_image",
    "event_names",
    "gpu_evidence_reason",
    "frontdoor_mode",
    "frontdoor_platform",
    "serving_leaf_sha256",
    "tls_spki_fingerprint",
    "receipt_count",
    "mesh_ca",
    "operator_key_status",
    "operator_keyset_sha256",
    "schema_version",
    "hpke_key_present",
    "snp_tcb",
    "snp_report_data",
    "report_data",
    "crypto_material_hash",
    "device_evidence_hash",
    "hpke_public_key",
    "collateral_count",
    "vcek_present",
    "cert_spki_der_bytes",
)


@dataclass
class Observation:
    """One observation of one workload's published evidence at one time."""

    observed_at: str
    vendor: str
    #: The log's own record-shape version, stamped on every record. It sits after
    #: the required fields because a dataclass cannot put a defaulted field ahead
    #: of them. It is written on every line regardless, so the log stays uniform.
    log_schema: str = LOG_SCHEMA
    workload: str = ""
    platform: str = ""
    measurement: str = ""
    tcb_version: str = ""
    source_url: str = ""
    http_status: int = 0
    response_sha256: str = ""
    raw_bytes: int = 0
    keyset_digest: str = ""
    os_image_hash: str = ""
    app_id: str = ""
    mr_kms: str = ""
    repo_commit: str = ""
    repo_url: str = ""
    tee_type: str = ""
    keyset_not_after: str = ""
    doc_format: str = ""
    cert_spki_sha256: str = ""
    doc_bytes: str = ""
    protocol: str = ""
    protocol_commit: str = ""
    release_id: str = ""
    release_bundle: str = ""
    workload_count: str = ""
    scope: str = ""
    operational_status: str = ""
    tls_binding_status: str = ""
    gpu_evidence_count: str = ""
    nonce: str = ""
    workload_digests: str = ""
    # Verification, not reachability. Empty means "not attempted or unavailable",
    # which is different from "false" and must stay distinguishable in the log.
    signature_valid: str = ""
    signature_error: str = ""
    tcb_status: str = ""
    tcb_reference: str = ""
    freshness_bound: str = ""
    freshness_note: str = ""
    tls_group: str = ""
    tls_pq: str = ""
    tls_error: str = ""
    # Declared capability surface, as opposed to observed identity. These record
    # what the provider says it offers: which key types it publishes for
    # verification, which domains it binds, whether it holds keys of its own.
    serving_role: str = ""
    e2ee_versions: str = ""
    receipt_key_algos: str = ""
    receipt_key_count: str = ""
    e2ee_key_algos: str = ""
    e2ee_key_count: str = ""
    tls_binding_count: str = ""
    tls_binding_domains: str = ""
    key_custody_provider: str = ""
    gpu_count: str = ""
    nvidia_arch: str = ""
    nvidia_evidence_count: str = ""
    provenance_image_digest: str = ""
    provenance_image: str = ""
    event_names: str = ""
    gpu_evidence_reason: str = ""
    frontdoor_mode: str = ""
    frontdoor_platform: str = ""
    serving_leaf_sha256: str = ""
    receipt_count: str = ""
    mesh_ca: str = ""
    operator_key_status: str = ""
    operator_keyset_sha256: str = ""
    schema_version: str = ""
    hpke_key_present: str = ""
    # SEV-SNP identity material. snp_tcb is what CVEs map against on the AMD
    # side, the same way tee_tcb_svn does on Intel.
    snp_tcb: str = ""
    snp_report_data: str = ""
    report_data: str = ""
    # The endorsed hashes and the bound key material. Recording them makes the
    # quote-to-key chain checkable after the fact instead of taken on faith.
    crypto_material_hash: str = ""
    device_evidence_hash: str = ""
    tls_spki_fingerprint: str = ""
    hpke_public_key: str = ""
    collateral_count: str = ""
    vcek_present: str = ""
    cert_spki_der_bytes: str = ""
    note: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[int, bytes]:
    """Fetch a URL, returning (status, raw bytes). Never raises on HTTP errors.

    A non-200 is data, not an exception: it is how the timeline records a vendor
    that stopped publishing.
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), resp.read()
    except urllib.error.HTTPError as e:
        return int(e.code), b""
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        logger.warning("fetch failed for %s: %s", url, e)
        return 0, b""


OBSERVATION_KEYS = set(RECORD_FIELDS) - {
    "observed_at",
    "vendor",
    "source_url",
    "http_status",
    "response_sha256",
    "raw_bytes",
}


def _nonce_of(url: str) -> str:
    """The challenge carried by a request-bound URL, if any."""
    if "nonce=" not in url:
        return ""
    return url.split("nonce=", 1)[1].split("&", 1)[0]


def collect(
    sources: list[Source],
    *,
    fetcher: Callable[[str], tuple[int, bytes]] | None = None,
    observed_at: str | None = None,
    measure_tls: bool = True,
    tls_runner: Callable[[list[str]], str] | None = None,
) -> list[Observation]:
    """Collect one observation pass over every source. Never raises per-source.

    Each source is both *parsed* (what did it publish, has that changed) and
    *checked* (was what it published actually valid). The two are independent:
    a source can parse cleanly and fail verification, which is the interesting
    case, and both facts are recorded rather than merged.
    """
    do_fetch = fetcher or fetch
    stamp = observed_at or utc_now_iso()
    observations: list[Observation] = []

    for source in sources:
        status, raw = do_fetch(source.url)
        digest = hashlib.sha256(raw).hexdigest() if raw else ""
        payload: Any = None

        if status == 200 and raw:
            try:
                payload = json.loads(raw.decode("utf-8"))
                parsed = source.parse(payload)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                parsed = [{"note": f"decode failed: {type(e).__name__}"}]
            except Exception as e:  # noqa: BLE001 - a parser bug must not kill the run
                logger.exception("parser failed for %s", source.vendor)
                parsed = [{"note": f"parser error: {type(e).__name__}"}]
        else:
            parsed = [{"note": f"fetch returned status {status}"}]

        # --- verification: signature, TCB, freshness, wire ---
        check_fields: dict[str, str] = {}
        if payload is not None and source.check is not None:
            try:
                checks = source.check(payload, _nonce_of(source.url))
                check_fields = checks.as_fields()
            except TypeError:
                # A checker that takes only the payload.
                try:
                    checks = source.check(payload)
                    check_fields = checks.as_fields()
                except Exception as e:  # noqa: BLE001
                    logger.warning("check failed for %s: %s", source.vendor, e)
                    check_fields = {"signature_error": f"check raised {type(e).__name__}"}
            except Exception as e:  # noqa: BLE001
                logger.warning("check failed for %s: %s", source.vendor, e)
                check_fields = {"signature_error": f"check raised {type(e).__name__}"}

        if measure_tls and source.host:
            try:
                from watch.checks import measure_tls_group

                group, err = measure_tls_group(source.host, runner=tls_runner)
                check_fields["tls_group"] = group
                check_fields["tls_error"] = err
                check_fields["tls_pq"] = (
                    "hybrid"
                    if group and any(g in group for g in ("MLKEM",))
                    else ("classical" if group else "")
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("tls measurement failed for %s: %s", source.host, e)

        for item in parsed:
            fields = {k: v for k, v in item.items() if k in OBSERVATION_KEYS}
            # Verification fills gaps the parser left blank, and never overwrites
            # something the parser found. The parser emits empty keys for fields
            # a given shape lacks, so a plain setdefault would never fire.
            for key, value in check_fields.items():
                if key in OBSERVATION_KEYS and str(value) and not fields.get(key):
                    fields[key] = value

            observations.append(
                Observation(
                    observed_at=stamp,
                    vendor=source.vendor,
                    source_url=source.url,
                    http_status=status,
                    response_sha256=digest,
                    raw_bytes=len(raw),
                    platform=str(fields.pop("platform", "") or source.platform),
                    workload=str(fields.pop("workload", "")),
                    note=str(fields.pop("note", "")),
                    nonce=str(fields.pop("nonce", "") or _nonce_of(source.url)),
                    **{k: str(v) for k, v in fields.items()},
                )
            )

    return observations


def heartbeat(observations: list[Observation], observed_at: str | None = None) -> Observation:
    """A per-run marker so a gap means 'the job stopped', not 'nothing happened'."""
    stamp = observed_at or utc_now_iso()
    vendors = sorted({o.vendor for o in observations})
    return Observation(
        observed_at=stamp,
        vendor="__heartbeat__",
        note=f"ran; {len(observations)} observations across {len(vendors)} vendors",
    )


def append_to_log(path: Path, observations: list[Observation]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for obs in observations:
            f.write(obs.to_json() + "\n")
    return len(observations)


@dataclass
class Anchor:
    """One anchoring attempt: which digest was submitted, and where it landed.

    An anchor is only worth recording if a stranger can find it again. The digest
    says what was submitted, and uuid plus rekor_url say where the transparency
    log entry is, so the proof can be fetched rather than taken on faith. A failed
    attempt is recorded too: an anchor that silently did not happen would leave
    the log looking anchored when it is not.
    """

    anchored_at: str
    digest: str
    anchored: bool
    uuid: str = ""
    log_index: str = ""
    rekor_url: str = ""
    reason: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def append_anchor(path: Path, anchor: Anchor) -> int:
    """Append one anchor record. Append-only, like the observation log."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(anchor.to_json() + "\n")
    return 1


def day_digest(paths: list[Path]) -> str:
    """SHA-256 over a set of files, for anchoring.

    Deterministic and re-derivable: a stranger can fetch the same published files
    and compute the same digest without knowing anything about this code.
    """
    h = hashlib.sha256()
    for path in sorted(paths):
        if path.exists():
            h.update(path.read_bytes())
    return h.hexdigest() if h.digest() != hashlib.sha256(b"").digest() else ""


def anchor_digest_soft(
    digest: str, *, anchor: Callable[[str], dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Anchor a digest, failing soft.

    An unanchored day is still a day of history; the anchor is what makes it
    provable to a stranger rather than merely published. Never lose the
    observation because the transparency log was unreachable.
    """
    if not digest:
        return {"anchored": False, "reason": "empty digest"}

    if anchor is None:

        def anchor(d: str) -> dict[str, Any]:  # type: ignore[misc]
            from watch.rekor_vendored import anchor_digest

            return anchor_digest(d)

    try:
        return {"anchored": True, "rekor": anchor(digest)}
    except Exception as e:  # noqa: BLE001
        logger.warning("anchoring failed: %s", e)
        return {"anchored": False, "reason": str(e)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", type=Path, default=Path("observations.jsonl"))
    parser.add_argument("--anchors", type=Path, default=Path("anchors.jsonl"))
    parser.add_argument("--anchor", action="store_true", help="Anchor the day's digest to Rekor.")
    parser.add_argument("--dry-run", action="store_true", help="Print without writing.")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    stamp = utc_now_iso()
    observations = collect(default_sources(), observed_at=stamp)
    records = observations + [heartbeat(observations, stamp)]

    if args.dry_run:
        for rec in records:
            print(rec.to_json())
        return 0

    written = append_to_log(args.log, records)
    logger.info("appended %d records to %s", written, args.log)

    if args.anchor:
        digest = day_digest([args.log])
        result = anchor_digest_soft(digest)
        rekor = result.get("rekor") or {}
        record = Anchor(
            anchored_at=stamp,
            digest=digest,
            anchored=bool(result.get("anchored")),
            uuid=str(rekor.get("uuid", "")),
            log_index=str(rekor.get("log_index") or ""),
            rekor_url=str(rekor.get("rekor_url", "")),
            reason=str(result.get("reason", "")),
        )
        append_anchor(args.anchors, record)
        if record.anchored:
            logger.info("anchored %s: %s", digest[:16], record.uuid)
        else:
            logger.warning("not anchored, recorded as such: %s", record.reason)

    return 0


if __name__ == "__main__":
    sys.exit(main())
