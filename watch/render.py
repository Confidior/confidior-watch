"""Render the timeline page from the observation log.

One page. Per vendor: what changed, when, and the headline number a stranger
actually wants -- **unchanged since X**.

What this page deliberately does not do:

- It does not grade. There is no verdict, no score, no ranking. This is the
  observation layer; grading belongs to the engine, and keeping them separate is
  the whole point of the split.
- It does not claim uptime, freshness guarantees, or completeness. It states
  what it observed and when.

The page's own wording is load-bearing. A public "we watch vendors" page
*implies* continuity, so if the crawl stops for three months it reads as an
abandoned service. The wording below states what this is: observations, gaps
visible, not a service, no commitment.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Fields whose change means the deployment changed. Deliberately excludes
#: ``raw_bytes`` and ``response_sha256``, which change whenever any byte of the
#: response moves -- including fields we do not care about. The response hash is
#: recorded in the log for verification; it is not identity.
IDENTITY_FIELDS = (
    "measurement",
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

FIELD_LABELS = {
    "measurement": "compose hash",
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


@dataclass
class Change:
    observed_at: str
    field: str
    before: str
    after: str


def load(path: Path) -> list[dict[str, Any]]:
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
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rec in records:
        if rec.get("vendor") == "__heartbeat__":
            continue
        groups[rec["vendor"]].append(rec)
    for rows in groups.values():
        rows.sort(key=lambda r: r.get("observed_at", ""))
    return dict(groups)


def find_changes(rows: list[dict[str, Any]]) -> list[Change]:
    """Changes in identity fields between consecutive *usable* observations."""
    usable = [r for r in rows if r.get("http_status") == 200]
    changes: list[Change] = []
    for prev, cur in zip(usable, usable[1:]):
        for f in IDENTITY_FIELDS:
            a, b = prev.get(f, ""), cur.get(f, "")
            if a and b and a != b:
                changes.append(Change(cur["observed_at"], f, a, b))
    return changes


def unchanged_since(rows: list[dict[str, Any]]) -> str:
    """The headline: when this vendor's identity last moved.

    Returns the timestamp of the last identity change, or the first observation
    if nothing has ever changed -- 'unchanged since first observation'.
    """
    usable = [r for r in rows if r.get("http_status") == 200]
    if not usable:
        return ""
    changes = find_changes(usable)
    return changes[-1].observed_at if changes else usable[0]["observed_at"]


def _short(value: str, n: int = 16) -> str:
    if not value:
        return "&mdash;"
    return html.escape(value[:n] + ("&hellip;" if len(value) > n else ""))


def render(records: list[dict[str, Any]], *, generated_at: str) -> str:
    groups = by_vendor(records)
    heartbeats = [r for r in records if r.get("vendor") == "__heartbeat__"]

    total = sum(len(v) for v in groups.values())
    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Continuity log &mdash; published attestation evidence over time</title>",
        "<style>",
        "body{font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;max-width:60rem;",
        "margin:2rem auto;padding:0 1rem;color:#1a1a1a}",
        "h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:.3rem}",
        "table{border-collapse:collapse;width:100%;margin:.5rem 0}",
        "td,th{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #eee}",
        "th{font-weight:600;color:#555}",
        ".muted{color:#666}.ok{color:#0a0}.bad{color:#a00}",
        ".headline{background:#f6f6f6;padding:.6rem .8rem;border-left:3px solid #888}",
        "code{background:#f2f2f2;padding:.05em .3em}",
        "</style></head><body>",
        "<h1>Continuity log</h1>",
        "<p>A scheduled crawl that records what vendors publish about their own ",
        "attestation evidence, over time, so that point-in-time observations become ",
        "a time series.</p>",
        "<p class='muted'>This page <strong>observes</strong>; it does not grade. There is no ",
        "verdict, score or ranking here, and none is implied. Observations only, gaps ",
        "visible, not a service, no uptime commitment. Each row carries the SHA-256 of ",
        "the raw response so you can re-fetch the source and compare.</p>",
        f"<p class='muted'>Generated {html.escape(generated_at)} &middot; ",
        f"{total} observations across {len(groups)} sources &middot; ",
        f"{len(heartbeats)} runs recorded.</p>",
    ]

    if not groups:
        parts.append("<p><strong>No observations yet.</strong> The first scheduled run has not "
                     "completed. A gap here is visible on purpose: silence never reads as a "
                     "claim on this page.</p>")

    for vendor in sorted(groups):
        rows = groups[vendor]
        usable = [r for r in rows if r.get("http_status") == 200]
        status = "ok" if usable and usable[-1].get("measurement") else "bad"
        since = unchanged_since(rows)
        last = rows[-1]

        parts.append(f"<h2>{html.escape(vendor)}</h2>")
        if since:
            parts.append(
                f"<p class='headline'>{html.escape(vendor)} unchanged since "
                f"<strong>{html.escape(since)}</strong></p>"
            )
        else:
            parts.append(
                "<p class='headline'>No usable observation yet &mdash; the source did not "
                "return readable evidence. That is recorded, not hidden.</p>"
            )

        parts.append("<table><tr><th>observed</th><th>http</th><th>identity</th></tr>")
        for row in rows[-12:]:
            ident = row.get("measurement") or row.get("keyset_digest") or ""
            cls = "ok" if row.get("http_status") == 200 and ident else "bad"
            note = row.get("note") or ""
            parts.append(
                f"<tr><td>{html.escape(row.get('observed_at','')[:19])}</td>"
                f"<td class='{cls}'>{row.get('http_status',0)}</td>"
                f"<td><code>{_short(ident, 24)}</code>"
                + (f" <span class='muted'>{html.escape(note)}</span>" if note else "")
                + "</td></tr>"
            )
        parts.append("</table>")

        changes = find_changes(rows)
        parts.append("<h3>Changes</h3>")
        if changes:
            parts.append("<table><tr><th>when</th><th>field</th><th>from</th><th>to</th></tr>")
            for ch in changes[-20:]:
                parts.append(
                    f"<tr><td>{html.escape(ch.observed_at[:19])}</td>"
                    f"<td>{html.escape(FIELD_LABELS.get(ch.field, ch.field))}</td>"
                    f"<td><code>{_short(ch.before)}</code></td>"
                    f"<td><code>{_short(ch.after)}</code></td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p class='muted'>No change recorded.</p>")

        parts.append(
            f"<p class='muted'>Latest source: <code>{html.escape(last.get('source_url',''))}</code></p>"
        )

    parts.append(
        "<hr><p class='muted'>Source code Apache-2.0. Observation data CC0 &mdash; "
        "public domain, reuse freely, no permission needed.</p>"
    )
    parts.append("</body></html>")
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", type=Path, default=Path("observations.jsonl"))
    parser.add_argument("--out", type=Path, default=Path("docs/index.html"))
    args = parser.parse_args(argv)

    from watch.clock import utc_now_iso

    records = load(args.log)
    generated = utc_now_iso()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(records, generated_at=generated))
    print(f"wrote {args.out} from {len(records)} records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
