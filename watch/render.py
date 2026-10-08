"""Render the timeline page from the observation log.

One page. Per vendor: what changed, when, and the headline a stranger wants to
know -- how long this vendor's published evidence has been stable, or that it
has not been observed long enough to say.

The design follows ``the site repository/DESIGN.md``: same tokens, same type
scale, same kicker pattern. This is a sub-page of the same brand, not a
separate project. Tokens are copied from the built site's ``:root`` rather than
transcribed from the spec, so they match what actually ships.

What this page deliberately does not do:

- It does not grade. No verdict, no score, no ranking. This is the observation
  layer; grading belongs to the engine, and keeping them separate is the point
  of the split.
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

UNREADABLE_DATE = "2026-10-09"

#: Copied from the site repository's built CSS ``:root`` (dark theme).
TOKENS = """
  --bg:#0b0d14; --bg-panel:#161822; --bg-panel-2:#1b1e2a; --bg-input:#10131d;
  --text:#e6e9f2; --text-dim:#a9b0c3; --text-mute:#8b93a7; --text-faint:#6b7387;
  --accent:#7b8cff; --accent-strong:#96a6ff; --accent-dim:rgba(123,140,255,.12);
  --green:#4dc729; --green-dim:rgba(77,199,41,.12);
  --red:#df3c30; --amber:#ffb224;
  --line:rgba(255,255,255,.08); --line-strong:rgba(255,255,255,.14);
  --mono:ui-monospace,"SF Mono","Cascadia Code","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Inter","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --container:1120px; --radius:6px; --radius-sm:3px;
  --ease:cubic-bezier(.22,.61,.36,1);
"""

CSS = f"""
:root{{{TOKENS}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
  font-size:16px;line-height:1.65;-webkit-font-smoothing:antialiased}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
.container{{width:100%;max-width:var(--container);margin-inline:auto;padding-inline:24px}}

nav{{position:sticky;top:0;z-index:10;background:var(--bg);
  border-bottom:1px solid var(--line);backdrop-filter:blur(8px)}}
nav .container{{display:flex;align-items:center;justify-content:space-between;
  height:56px;gap:24px}}
nav .brand{{font-family:var(--mono);font-size:13px;letter-spacing:.06em;
  text-transform:uppercase;color:var(--text-dim)}}
nav .links{{display:flex;gap:20px;font-size:14px}}

main{{padding-block:clamp(3rem,6vw,5rem)}}

.kicker{{display:flex;align-items:center;gap:12px;font-family:var(--mono);
  font-size:13px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--text-mute);margin:0 0 16px}}
.kicker .num{{color:var(--accent)}}

h1{{font-size:clamp(1.75rem,4vw,2.5rem);line-height:1.1;margin:0 0 20px;
  font-weight:650;letter-spacing:-.02em}}
h2{{font-size:1.25rem;margin:0;font-weight:600;font-family:var(--mono);
  letter-spacing:-.01em}}
h3{{font-size:.8rem;font-family:var(--mono);text-transform:uppercase;
  letter-spacing:.08em;color:var(--text-mute);margin:28px 0 10px;font-weight:600}}

.lede{{font-size:clamp(1.05rem,1.6vw,1.2rem);line-height:1.6;
  color:var(--text-dim);max-width:62ch;margin:0 0 16px}}
.note{{color:var(--text-faint);font-size:.875rem;max-width:62ch;margin:0 0 8px}}
.mono{{font-family:var(--mono);font-size:.85em}}
code.hash{{font-family:var(--mono);font-size:.78rem;color:var(--text);
  background:var(--bg-input);border:1px solid var(--line);border-radius:var(--radius-sm);
  padding:2px 7px;user-select:all;word-break:break-all;cursor:text}}
a.recheck{{font-size:.78rem;font-family:var(--mono);white-space:nowrap}}

.card{{background:var(--bg-panel);border:1px solid var(--line);
  border-radius:var(--radius);padding:24px;margin:20px 0;
  transition:border-color .18s var(--ease)}}
.card:hover{{border-color:var(--line-strong)}}
.card-head{{display:flex;align-items:baseline;justify-content:space-between;
  gap:16px;flex-wrap:wrap;margin-bottom:14px}}

.chip{{display:inline-block;font-family:var(--mono);font-size:11px;
  letter-spacing:.06em;text-transform:uppercase;padding:3px 10px;
  border-radius:999px;border:1px solid var(--line-strong);color:var(--text-mute);
  white-space:nowrap}}
.chip-green{{color:var(--green);border-color:#4dc72966;background:var(--green-dim)}}
.chip-amber{{color:var(--amber);border-color:#ffb22466;background:rgba(255,178,36,.1)}}
.chip-red{{color:var(--red);border-color:#df3c3066;background:rgba(223,60,48,.1)}}
.chip-dim{{color:var(--text-faint);border-color:var(--line)}}

.facts{{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 18px}}
.fact{{font-family:var(--mono);font-size:11px;letter-spacing:.04em;
  padding:4px 10px;border-radius:var(--radius-sm);border:1px solid var(--line);
  background:var(--bg-panel-2);color:var(--text-dim)}}
.fact b{{color:var(--text);font-weight:500}}
.fact.good{{border-color:#4dc72944}} .fact.good b{{color:var(--green)}}
.fact.bad{{border-color:#df3c3044}} .fact.bad b{{color:var(--red)}}
.fact.none{{border-color:var(--line)}} .fact.none b{{color:var(--text-faint)}}

.headline{{font-family:var(--mono);font-size:.9rem;color:var(--text-dim);
  padding:10px 14px;background:var(--bg-panel-2);border-radius:var(--radius-sm);
  border-left:2px solid var(--accent);margin:0 0 18px}}
.headline .stamp{{color:var(--text)}}
.headline.first{{border-left-color:var(--text-faint)}}

table{{border-collapse:collapse;width:100%;font-size:.875rem}}
th{{text-align:left;font-family:var(--mono);font-size:11px;letter-spacing:.06em;
  text-transform:uppercase;color:var(--text-faint);font-weight:500;
  padding:0 12px 8px 0;border-bottom:1px solid var(--line)}}
td{{padding:7px 12px 7px 0;border-bottom:1px solid var(--line);
  color:var(--text-dim);vertical-align:top}}
td.m{{font-family:var(--mono);color:var(--text);font-size:.8rem}}
td.ok{{color:var(--green);font-family:var(--mono)}}
td.bad{{color:var(--red);font-family:var(--mono)}}
tr:last-child td{{border-bottom:none}}

.empty{{color:var(--text-faint);font-size:.875rem;margin:6px 0 0}}
footer{{border-top:1px solid var(--line);padding-block:32px;margin-top:48px;
  color:var(--text-faint);font-size:.8rem}}
footer .container{{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}}
"""


#: Providers checked on 2026-10-09 that do not publish attestation evidence an
#: anonymous reader can verify. Each entry is an observation about publication
#: posture, with the exact response received. Not a judgement, and not a claim
#: that these providers do no verification -- several publish evidence through
#: their own authenticated tooling, which is a different thing from publishing
#: it openly.
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


def stability(rows: list[dict[str, Any]]) -> tuple[str, int]:
    """(since, usable_count) -- and the caller decides how to word it.

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


def _short(value: str, n: int = 16) -> str:
    if not value:
        return "&mdash;"
    return html.escape(value[:n] + ("&hellip;" if len(value) > n else ""))


def strip_query(url: str) -> str:
    """The endpoint without its per-run parameters.

    A request-bound source carries a fresh nonce each run, which is not part of
    the endpoint's identity and should not appear as though it were.
    """
    return url.split("?", 1)[0]


def render(records: list[dict[str, Any]], *, generated_at: str) -> str:
    groups = by_vendor(records)
    heartbeats = [r for r in records if r.get("vendor") == "__heartbeat__"]

    observed = sum(len(v) for v in groups.values())
    runs = len(heartbeats)

    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Continuity log &mdash; published attestation evidence over time</title>",
        f"<style>{CSS}</style>",
        "</head><body>",
        '<nav><div class="container">',
        '<span class="brand">confidior / continuity log</span>',
        '<span class="links">'
        '<a href="https://confidior.com">confidior.com</a>'
        '<a href="https://github.com/Confidior">github</a>'
        "</span></div></nav>",
        '<main><div class="container">',
        '<p class="kicker"><span class="num">00</span> continuity log</p>',
        "<h1>Published attestation evidence, over time.</h1>",
        '<p class="lede">A scheduled crawl that records what vendors publish about their '
        "own attestation evidence, so that point-in-time observations become a time "
        "series.</p>",
        '<p class="note">This page observes; it does not grade. No verdict, score or '
        "ranking appears here and none is implied. Observations only, gaps visible, not "
        "a service, no uptime commitment. Every row carries the SHA-256 of the raw "
        "response so you can re-fetch the source and compare.</p>",
        f'<p class="note">Generated <span class="mono">{html.escape(generated_at)}</span>'
        f" &middot; {observed} observations across {len(groups)} sources &middot; "
        f"{runs} run{'' if runs == 1 else 's'} recorded.</p>",
        '<p class="note">Each run verifies, not merely fetches: the quote '
        "signature against the vendor's root of trust, the TCB security version, "
        "whether the response was bound to a challenge this run generated, and "
        "what key exchange the endpoint negotiates. A check that could not run is "
        "shown as <em>not attempted</em> rather than as a failure, because those "
        "are different facts.</p>",
    ]

    if not groups:
        parts.append(
            '<div class="card"><p><strong>No observations yet.</strong> The first '
            "scheduled run has not completed. A gap here is visible on purpose: "
            "silence never reads as a claim on this page.</p></div>"
        )

    for i, vendor in enumerate(sorted(groups), start=1):
        rows = groups[vendor]
        usable = [r for r in rows if r.get("http_status") == 200]
        since, usable_count = stability(rows)
        last = rows[-1]
        healthy = bool(usable) and bool(usable[-1].get("measurement"))

        parts.append(f'<p class="kicker" style="margin-top:40px">'
                     f'<span class="num">{i:02d}</span> {html.escape(vendor)}</p>')

        if since and usable_count >= 2:
            parts.append(
                '<p class="headline">unchanged since '
                f'<span class="stamp">{html.escape(since[:19])}</span> '
                f'<span class="mono">({usable_count} observations)</span></p>'
            )
        elif since:
            parts.append(
                '<p class="headline first">first observed '
                f'<span class="stamp">{html.escape(since[:19])}</span> '
                "&mdash; one observation, so there is nothing to compare against yet</p>"
            )
        else:
            parts.append(
                '<p class="headline">No usable observation yet &mdash; the source did '
                "not return readable evidence. That is recorded, not hidden.</p>"
            )

        # Verification state, stated as facts rather than a verdict. These are
        # checks that ran this run, not an assessment of the provider.
        latest = usable[-1] if usable else None
        if latest:
            facts: list[str] = []

            def fact(label: str, value: str, cls: str = "none") -> str:
                return (f'<span class="fact {cls}">{html.escape(label)} '
                        f"<b>{html.escape(value)}</b></span>")

            sig = latest.get("signature_valid", "")
            if sig == "true":
                facts.append(fact("quote signature", "verified", "good"))
            elif sig == "false":
                facts.append(fact("quote signature", "failed", "bad"))
            else:
                facts.append(fact("quote signature", "not attempted", "none"))

            tcb = latest.get("tcb_version", "")
            facts.append(fact("tcb", tcb[:16], "good" if tcb else "none"))

            fresh = latest.get("freshness_bound", "")
            if fresh == "true":
                facts.append(fact("freshness", "bound", "good"))
            elif fresh == "false":
                facts.append(fact("freshness", "not bound", "bad"))
            elif fresh == "unbound":
                facts.append(fact("freshness", "unbound", "none"))
            else:
                facts.append(fact("freshness", "not attempted", "none"))

            tls = latest.get("tls_group", "")
            facts.append(fact("key exchange", tls or "not measured",
                              "good" if "MLKEM" in tls else "none"))

            if latest.get("http_status") != 200:
                facts.append(fact("http", str(latest.get("http_status")), "bad"))

            parts.append('<div class="facts">' + "".join(facts) + "</div>")

        parts.append('<div class="card">')
        parts.append(
            '<div class="card-head">'
            f'<h2>{html.escape(vendor)}</h2>'
            f'<span class="chip {"chip-green" if healthy else "chip-red"}">'
            f'{"observed" if healthy else "unreadable"}</span></div>'
        )
        parts.append(
            "<table><tr><th>observed</th><th>http</th><th>identity</th>"
            "<th>response sha256</th></tr>"
        )
        for row in rows[-12:]:
            ident = row.get("measurement") or row.get("keyset_digest") or ""
            digest = row.get("response_sha256") or ""
            cls = "ok" if row.get("http_status") == 200 and ident else "bad"
            note = row.get("note") or ""
            src = row.get("source_url") or ""
            # The hash is shown whole and selectable, and the row links to the
            # endpoint so a reader can re-fetch it and compare. A truncated hash
            # is a texture, not evidence.
            parts.append(
                f'<tr><td class="m">{html.escape(row.get("observed_at", "")[:19])}</td>'
                f'<td class="{cls}">{row.get("http_status", 0)}</td>'
                f'<td class="m">{html.escape(ident) if ident else "&mdash;"}'
                + (f' <span class="note">{html.escape(note)}</span>' if note else "")
                + "</td>"
                f'<td><code class="hash">{html.escape(digest) or "&mdash;"}</code>'
                + (f'<br><a class="recheck" href="{html.escape(src)}">re-fetch &rarr;</a>' if src else "")
                + "</td></tr>"
            )
        parts.append("</table>")
        parts.append(
            '<p class="empty">To check a row: open <em>re-fetch</em>, save the response, '
            "and compare its SHA-256 with the hash above.</p>"
        )

        changes = find_changes(rows)
        parts.append("<h3>What was verified</h3>")
        checks = [
            ("quote signature",
             "the quote verifies against the vendor's root of trust"),
            ("TCB SVN",
             "the security version number, which moves on microcode and module "
             "updates and is what CVEs map against"),
            ("freshness",
             "the response carried a challenge this run generated, so it was "
             "produced after we asked"),
            ("key exchange",
             "what TLS group the endpoint negotiates when offered a post-quantum "
             "hybrid"),
        ]
        parts.append("<table><tr><th>check</th><th>what it means</th></tr>")
        for name, meaning in checks:
            parts.append(f"<tr><td class='m'>{html.escape(name)}</td>"
                         f"<td>{html.escape(meaning)}</td></tr>")
        parts.append("</table>")

        parts.append("<h3>Changes</h3>")
        if changes:
            parts.append(
                "<table><tr><th>when</th><th>field</th><th>from</th><th>to</th></tr>"
            )
            for ch in changes[-20:]:
                parts.append(
                    f'<tr><td class="m">{html.escape(ch.observed_at[:19])}</td>'
                    f"<td>{html.escape(FIELD_LABELS.get(ch.field, ch.field))}</td>"
                    f'<td class="m">{_short(ch.before)}</td>'
                    f'<td class="m">{_short(ch.after)}</td></tr>'
                )
            parts.append("</table>")
        else:
            parts.append('<p class="empty">No change recorded.</p>')

        parts.append(
            '<p class="empty">Source: '
            f'<span class="mono">{html.escape(strip_query(last.get("source_url", "")))}</span></p>'
        )
        parts.append("</div>")

    # --- what is not readable anonymously ---
    # This is the most useful thing the crawl found, and it is a fact about
    # public endpoints that anyone can re-check. It is not a security claim.
    parts.append(
        '<p class="kicker" style="margin-top:56px">'
        '<span class="num">%02d</span> not readable anonymously</p>' % (len(groups) + 1)
    )
    parts.append(
        '<p class="lede">Eight of the twelve confidential-inference endpoints we '
        "probed do not serve attestation evidence to an anonymous reader. Four do. "
        "This is a statement about publication posture, checked on "
        f'<span class="mono">{html.escape(UNREADABLE_DATE)}</span>, not a statement '
        "about whether these providers verify anything internally.</p>"
    )
    parts.append('<div class="card"><table>'
                 "<tr><th>provider</th><th>endpoint</th><th>response</th><th>note</th></tr>")
    for name, endpoint, code, note in UNREADABLE:
        cls = "ok" if code == "200" else "bad"
        parts.append(
            f'<tr><td class="m">{html.escape(name)}</td>'
            f'<td class="m">{html.escape(endpoint)}</td>'
            f'<td class="{cls}">{html.escape(code)}</td>'
            f"<td>{html.escape(note)}</td></tr>"
        )
    parts.append("</table></div>")

    parts.append("</div></main>")
    parts.append(
        '<footer><div class="container">'
        "<span>Source code Apache-2.0. Observation data CC0 &mdash; public domain, "
        "reuse freely, no permission needed.</span>"
        "<span>Observations, not assessments.</span>"
        "</div></footer>"
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
