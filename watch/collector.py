"""confidior-watch: a continuity log for published attestation evidence.

A scheduled crawl that records what vendors publish about their own attestation
evidence, over time, so that point-in-time observations become a time series.

A single capture is an anecdote. A thousand captures is a history. This is the
mechanism that turns one into the other.

What it is not: a service, a dashboard, a grader. It observes; the engine judges.
There is no uptime promise and no account. Its worst failure is a gap in a
timeline, and for an evidence archive silence never reads as a claim.
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

#: Every field written to the log. Kept explicit so the log is self-describing
#: and a reader never has to infer the schema from examples.
RECORD_FIELDS = (
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
)


@dataclass
class Observation:
    """One observation of one workload's published evidence at one time."""

    observed_at: str
    vendor: str
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


OBSERVATION_KEYS = set(RECORD_FIELDS) - {"observed_at", "vendor", "source_url",
                                         "http_status", "response_sha256", "raw_bytes"}


def collect(
    sources: list[Source],
    *,
    fetcher: Callable[[str], tuple[int, bytes]] | None = None,
    observed_at: str | None = None,
) -> list[Observation]:
    """Collect one observation pass over every source. Never raises per-source."""
    do_fetch = fetcher or fetch
    stamp = observed_at or utc_now_iso()
    observations: list[Observation] = []

    for source in sources:
        status, raw = do_fetch(source.url)
        digest = hashlib.sha256(raw).hexdigest() if raw else ""

        if status == 200 and raw:
            try:
                parsed = source.parse(json.loads(raw.decode("utf-8")))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                parsed = [{"note": f"decode failed: {type(e).__name__}"}]
            except Exception as e:  # noqa: BLE001 - a parser bug must not kill the run
                logger.exception("parser failed for %s", source.vendor)
                parsed = [{"note": f"parser error: {type(e).__name__}"}]
        else:
            parsed = [{"note": f"fetch returned status {status}"}]

        for item in parsed:
            fields = {k: v for k, v in item.items() if k in OBSERVATION_KEYS}
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


def anchor_digest_soft(digest: str, *, anchor: Callable[[str], dict[str, Any]] | None = None) -> dict[str, Any]:
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
        if result.get("anchored"):
            logger.info("anchored %s: %s", digest[:16], result["rekor"])
        else:
            logger.warning("not anchored: %s", result.get("reason"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
