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

from watch.checks import Checks, gate_summary, score_gates

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
#: The palette is not invented here. It is the engine's own, taken from
#: src/export/badge.py, which docs/the internal design note names as the source of
#: truth for the visual language. This page previously carried a slightly
#: different accent and surface ramp, which meant the log and the badge and the
#: site disagreed about what green and red mean. They do not disagree now.
#:
#: Divergence that remains, and why: this page uses a lighter text ramp
#: (#e5e7eb / #9ca3af / #6b7280 are the engine's; the middle and faint values
#: here match those exactly). Anything not sourced from badge.py is marked.
TOKENS = """
  /* from src/export/badge.py */
  --green:#4dc729; --red:#df3c30; --amber:#f59e0b; --blue:#3b82f6;
  --neutral:#999999;
  --bg-panel:#161822; --bg-panel-2:#1e2030;
  --text:#e5e7eb; --text-dim:#9ca3af; --text-faint:#6b7280;
  /* page-local: surface ramp and states the badge does not define */
  --text-mute:#8b93a7;
  --bg:#0f1117; --bg-input:#111318;
  --bg-grad:linear-gradient(180deg,#161822 0%,#1a1d2a 100%);
  --accent:var(--blue); --accent-dim:rgba(59,130,246,.12);
  --green-dim:rgba(77,199,41,.12);
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
.chip-green{{color:var(--green);border-color:rgba(77,199,41,.4);background:var(--green-dim)}}
.chip-amber{{color:var(--amber);border-color:rgba(245,158,11,.4);background:rgba(245,158,11,.1)}}
.chip-red{{color:var(--red);border-color:rgba(223,60,48,.4);background:rgba(223,60,48,.1)}}
.chip-dim{{color:var(--text-faint);border-color:var(--line)}}

.facts{{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 18px}}
.recheck-note{{font-family:var(--mono);font-size:.78rem;color:var(--text-faint)}}
.fact{{font-family:var(--mono);font-size:11px;letter-spacing:.04em;
  padding:4px 10px;border-radius:var(--radius-sm);border:1px solid var(--line);
  background:var(--bg-panel-2);color:var(--text-dim)}}
.fact b{{color:var(--text);font-weight:500}}
.fact.good{{border-color:rgba(77,199,41,.27)}} .fact.good b{{color:var(--green)}}
.fact.bad{{border-color:rgba(223,60,48,.27)}} .fact.bad b{{color:var(--red)}}
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
.gatebar{{margin:6px 0 10px;display:flex;gap:6px;flex-wrap:wrap}}
.g{{font-family:var(--mono);font-size:.72rem;padding:2px 7px;border-radius:3px;
   border:1px solid var(--line);white-space:nowrap}}
.g-good{{border-color:rgba(77,199,41,.5);color:var(--green)}}
.g-warning{{color:var(--amber)}}
.g-bad{{border-color:var(--red);color:var(--red)}}
.g-unverifiable{{color:var(--neutral);opacity:.85}}
.g-na{{color:var(--text-faint);opacity:.6}}
.legend{{margin:0 0 28px;border:1px solid var(--line);border-radius:var(--radius);
  background:var(--bg-panel)}}
.legend summary{{cursor:pointer;padding:12px 18px;font-family:var(--mono);
  font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--text-mute)}}
.legend table{{margin:0;padding:0 18px 14px}}
.legend td:first-child{{white-space:nowrap;color:var(--text)}}
/* Provider cards read as panels, matching the engine web UI, so the log looks
   like the same product rather than a side project. */
.vendor{{border:1px solid var(--line);border-radius:var(--radius);
  background:var(--bg-panel);padding:22px 24px;margin:0 0 22px}}
.vendor:hover{{border-color:var(--line-strong)}}
.vendor-head{{display:flex;align-items:baseline;justify-content:space-between;
  gap:14px;flex-wrap:wrap;margin:0 0 4px}}
.vendor-name{{font-family:var(--mono);font-size:1rem;letter-spacing:-.01em;
  color:var(--text);margin:0;font-weight:600}}
.vendor-sub{{font-family:var(--mono);font-size:11px;letter-spacing:.05em;
  text-transform:uppercase;color:var(--text-faint)}}

/* Every observation is collapsible, and the collapsed line already carries the
   facts a reader scans for. Open one to see every field the run recorded.
   Nothing is hidden: the detail is closed, not absent. */
.obs{{border:1px solid var(--line);border-radius:var(--radius-sm);
  background:var(--bg-panel-2);margin:0 0 8px}}
.obs summary{{cursor:pointer;padding:9px 12px;display:flex;gap:12px;
  align-items:baseline;flex-wrap:wrap;font-family:var(--mono);font-size:.78rem;
  color:var(--text-dim);list-style:none}}
.obs summary::-webkit-details-marker{{display:none}}
.obs summary::before{{content:"\\25B8";color:var(--text-faint)}}
.obs[open] summary::before{{content:"\\25BE"}}
.obs summary:hover{{color:var(--text)}}
.obs summary .when{{color:var(--text)}}
.obs summary .ident{{color:var(--text-mute);word-break:break-all}}
.obs summary .end{{margin-left:auto;display:flex;gap:10px;align-items:baseline}}
.obs .body{{padding:2px 12px 12px;border-top:1px solid var(--line)}}
.obs td{{padding:4px 12px 4px 0;font-size:.78rem}}
.obs .k{{font-family:var(--mono);color:var(--text-mute);white-space:nowrap}}
.obs .v{{font-family:var(--mono);color:var(--text);word-break:break-all;
  user-select:all;cursor:text}}
.obs .v.faint{{color:var(--text-faint)}}
.obs h4{{font-family:var(--mono);font-size:.72rem;text-transform:uppercase;
  letter-spacing:.08em;color:var(--text-mute);margin:16px 0 8px;font-weight:600}}
.obs .facts{{margin:0 0 4px}}
.obs table.kv td.k{{width:38%}}
.obs pre.blob{{margin:0 0 10px;padding:10px 12px;background:var(--bg-input);
  border:1px solid var(--line);border-radius:var(--radius-sm);
  font-family:var(--mono);font-size:.72rem;color:var(--text-dim);
  white-space:pre-wrap;word-break:break-all;max-height:320px;overflow:auto}}

/* A summary strip, so the page opens with the state of the register rather
   than with prose. Same shape as the dotcom provider hero. */
.summary{{display:flex;flex-wrap:wrap;gap:0;margin:0 0 26px;
  border:1px solid var(--line);border-radius:var(--radius);
  background:var(--bg-panel);overflow:hidden}}
.summary div{{flex:1 1 120px;padding:14px 18px;border-right:1px solid var(--line)}}
.summary div:last-child{{border-right:none}}
.summary .k{{font-family:var(--mono);font-size:10px;letter-spacing:.08em;
  text-transform:uppercase;color:var(--text-faint);display:block;margin-bottom:5px}}
.summary .v{{font-family:var(--mono);font-size:1.35rem;color:var(--text);
  line-height:1.1;font-weight:600}}
.summary .v small{{font-size:.7rem;color:var(--text-dim);font-weight:400}}

footer{{border-top:1px solid var(--line);padding-block:32px;margin-top:48px;
  color:var(--text-faint);font-size:.8rem}}
footer .container{{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}}
footer a{{color:var(--text-dim)}}
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


def _fmt_keys(algos: str, count: str) -> str:
    """Render a key inventory as "n: a, b" so absence is visibly distinct."""
    if not algos and not count:
        return ""
    return f"{count or '0'}: {algos}" if algos else f"{count}"


def _count_word(count: str, reason: str) -> str:
    """An empty evidence list is a finding, and its stated reason is the useful part."""
    if count == "":
        return ""
    if count != "0":
        return count
    return f"none published ({reason})" if reason else "none published"


def _recheck_link(src: str) -> str:
    """A re-fetch affordance, or an honest statement that there cannot be one.

    A source challenged with a nonce cannot be re-fetched from a link: the nonce
    is single-use and replay-protected, so the same URL returns 409. Offering a
    link that fails would be worse than offering none, so the endpoint is shown
    and the reason stated.
    """
    if not src:
        return ""
    base = strip_query(src)
    if "nonce=" in src:
        return (f'<a class="recheck" href="{html.escape(base)}">endpoint &rarr;</a>'
                '<br><span class="recheck-note">not re-fetchable: this response was '
                "bound to a single-use challenge, so the same URL now returns 409</span>")
    return f'<a class="recheck" href="{html.escape(src)}">re-fetch &rarr;</a>'


def strip_query(url: str) -> str:
    """The endpoint without its per-run parameters.

    A request-bound source carries a fresh nonce each run, which is not part of
    the endpoint's identity and should not appear as though it were.
    """
    return url.split("?", 1)[0]


def _fact(label: str, value: str, cls: str = "none") -> str:
    return (f'<span class="fact {cls}">{html.escape(label)} '
            f"<b>{html.escape(value)}</b></span>")


def _row_facts(row: dict[str, Any]) -> list[str]:
    """The verification state of one observation, as facts rather than a verdict.

    These describe the run that produced *this* record. They used to be lifted
    to the vendor panel from `usable[-1]`, so a vendor with several
    observations showed only the newest one's state and the rest were lost.
    """
    facts: list[str] = []

    sig = row.get("signature_valid", "")
    if sig == "true":
        facts.append(_fact("quote signature", "verified", "good"))
    elif sig == "false":
        facts.append(_fact("quote signature", "failed", "bad"))
    else:
        facts.append(_fact("quote signature", "not attempted", "none"))

    # A chip with an empty value reads as a blank label. When the field is
    # absent the chip says so, the way the signature and freshness chips do.
    tcb = row.get("tcb_version", "")
    if tcb:
        facts.append(_fact("tcb", tcb[:16], "good"))
    else:
        facts.append(_fact("tcb", "not reported", "none"))

    fresh = row.get("freshness_bound", "")
    if fresh == "true":
        facts.append(_fact("freshness", "bound", "good"))
    elif fresh == "false":
        facts.append(_fact("freshness", "not bound", "bad"))
    elif fresh == "unbound":
        facts.append(_fact("freshness", "unbound", "none"))
    else:
        facts.append(_fact("freshness", "not attempted", "none"))

    tls = row.get("tls_group", "")
    facts.append(_fact("key exchange", tls or "not measured",
                       "good" if "MLKEM" in tls else "none"))

    if row.get("http_status") != 200:
        facts.append(_fact("http", str(row.get("http_status")), "bad"))

    return facts


def _gate_parts(row: dict[str, Any]) -> list[str]:
    """The gate grid for one observation: which claims survived, how strongly."""
    checks = Checks(
        signature_valid=str(row.get("signature_valid") or ""),
        signature_error=str(row.get("signature_error") or ""),
        tcb_version=str(row.get("tcb_version") or ""),
        tcb_status=str(row.get("tcb_status") or ""),
        tcb_reference=str(row.get("tcb_reference") or ""),
        freshness_bound=str(row.get("freshness_bound") or ""),
        freshness_note=str(row.get("freshness_note") or ""),
        tls_group=str(row.get("tls_group") or ""),
        tls_error=str(row.get("tls_error") or ""),
    )
    gates = score_gates(checks, row)
    counts = gate_summary(gates)

    headline = " ".join(
        f'<span class="g g-{status}">{counts.get(status, 0)} {status}</span>'
        for status in ("good", "warning", "bad", "unverifiable")
        if counts.get(status)
    )
    out = [
        '<p class="note">Checks run, for this observation: '
        f"{len(gates)} independent checks, each with its own result and its own "
        "evidence strength. This is a record of what was checked, not a rating.</p>",
        f'<p class="gatebar">{headline}</p>',
        "<table><tr><th>gate</th><th>status</th><th>evidence</th></tr>",
    ]
    for gate in gates:
        out.append(
            f'<tr><td class="m">{html.escape(gate.name)}</td>'
            f'<td><span class="g g-{gate.status.value}">'
            f'{html.escape(gate.status.value)}</span></td>'
            f'<td class="m">{html.escape(gate.strength.value)}</td></tr>'
        )
    out.append("</table>")
    return out


#: The curated surface, in reading order. Each entry is a label and the keys it
#: reads from one observation. This is per-observation like every other field.
SURFACE_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("serving role", ("serving_role",)),
    ("platform", ("platform",)),
    ("tee type", ("tee_type",)),
    ("E2EE protocol versions", ("e2ee_versions",)),
    ("receipt keys published", ("receipt_key_algos", "receipt_key_count")),
    ("E2EE keys published", ("e2ee_key_algos", "e2ee_key_count")),
    ("TLS bindings", ("tls_binding_domains", "tls_binding_count")),
    ("keyset expires", ("keyset_not_after",)),
    ("key custody held by", ("key_custody_provider",)),
    ("GPU architecture", ("nvidia_arch",)),
    ("GPU evidence attached", ("nvidia_evidence_count", "gpu_evidence_reason")),
    ("source repo", ("repo_url",)),
    ("source commit", ("repo_commit",)),
    ("image provenance", ("provenance_image",)),
    ("measured boot events", ("event_names",)),
    ("attestation protocol", ("protocol",)),
    ("protocol commit", ("protocol_commit",)),
    ("release", ("release_id",)),
    ("schema version", ("schema_version",)),
    ("declared scope", ("scope",)),
    ("provider self-status", ("operational_status",)),
    ("TLS binding status", ("tls_binding_status",)),
    ("front door mode", ("frontdoor_mode",)),
    ("serving leaf", ("serving_leaf_sha256",)),
    ("operator key status", ("operator_key_status",)),
    ("receipts published", ("receipt_count",)),
    ("HPKE key published", ("hpke_key_present",)),
    ("document format", ("doc_format",)),
)


def _surface_row(row: dict[str, Any]) -> list[tuple[str, str]]:
    """The curated surface for one observation, filled fields only."""
    out: list[tuple[str, str]] = []
    for label, keys in SURFACE_FIELDS:
        if label.startswith("receipt keys") or label.startswith("E2EE keys") \
                or label.startswith("TLS bindings"):
            value = _fmt_keys(row.get(keys[0], ""), row.get(keys[1], ""))
        elif label.startswith("GPU evidence"):
            value = _count_word(row.get(keys[0], ""), row.get(keys[1], ""))
        else:
            value = row.get(keys[0], "")
        if value:
            out.append((label, value))
    return out


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

    # Open with the state of the register, not with prose. Same shape as the
    # dotcom provider hero: a row of counts a reader can take in at a glance.
    verified = sum(
        1 for v in groups.values() for r in v if r.get("signature_valid") == "true"
    )
    readable = sum(
        1 for v in groups.values() for r in v if r.get("http_status") == 200
    )
    # Two counts, two sources, kept separate on purpose. `verified`/`readable`
    # come from the log: how many observed responses we could read, and how
    # many of those carried a quote that verified. `unreadable_anon` comes from
    # the probed-endpoint list below, which covers endpoints we never logged a
    # record for. Subtracting one from the other (observed - readable) produced
    # a number that was wrong on every axis: it read as a count of unreadable
    # endpoints while measuring observations.
    unreadable_anon = sum(1 for e in UNREADABLE if e[2] != "200")
    parts.append(
        '<div class="summary">'
        f'<div><span class="k">sources</span><span class="v">{len(groups)}</span></div>'
        f'<div><span class="k">observations</span><span class="v">{observed}</span></div>'
        f'<div><span class="k">quote verified</span><span class="v">{verified}'
        f'<small> of {readable} readable</small></span></div>'
        f'<div><span class="k">not readable</span><span class="v">{unreadable_anon}'
        f'<small> of {len(UNREADABLE)} probed</small></span></div>'
        f'<div><span class="k">runs recorded</span><span class="v">{runs}</span></div>'
        "</div>"
    )

    if not groups:
        parts.append(
            '<div class="card"><p><strong>No observations yet.</strong> The first '
            "scheduled run has not completed. A gap here is visible on purpose: "
            "silence never reads as a claim on this page.</p></div>"
        )

    parts.append(
        '<details class="legend"><summary>What each check means</summary>'
        "<table><tr><th>check</th><th>what it means</th></tr>"
        "<tr><td class='m'>quote signature</td>"
        "<td>the quote verifies against the vendor's root of trust: Intel's PCK "
        "certificate chain for TDX, the AWS Nitro root for Nitro</td></tr>"
        "<tr><td class='m'>TCB SVN</td>"
        "<td>the security version number of the platform, one byte per component. "
        "It moves on microcode and module updates and is the field CVEs map "
        "against</td></tr>"
        "<tr><td class='m'>freshness</td>"
        "<td>the response carried a challenge this run generated, so it was "
        "produced after we asked rather than replayed</td></tr>"
        "<tr><td class='m'>key exchange</td>"
        "<td>what TLS group the endpoint negotiates when offered a post-quantum "
        "hybrid</td></tr>"
        "</table></details>"
    )

    for i, vendor in enumerate(sorted(groups), start=1):
        rows = groups[vendor]
        usable = [r for r in rows if r.get("http_status") == 200]
        since, usable_count = stability(rows)
        last = rows[-1]
        healthy = bool(usable) and bool(usable[-1].get("measurement"))

        # Each vendor is a panel with a header, matching the engine web UI so
        # the log reads as the same product rather than a side project.
        platform = str((usable[-1] if usable else rows[-1]).get("platform") or "")
        parts.append('<section class="vendor">')
        parts.append(
            '<div class="vendor-head">'
            f'<h2 class="vendor-name">{html.escape(vendor)}</h2>'
            '<span class="vendor-sub">'
            f'<span class="chip {"chip-green" if healthy else "chip-red"}">'
            f'{"observed" if healthy else "unreadable"}</span> '
            f'{i:02d}'
            + (f" &middot; {html.escape(platform)}" if platform else "")
            + "</span></div>"
        )

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

        # What belongs to the vendor, and only to the vendor: where it was
        # first or last seen, how many observations there are, and whether any
        # of them was readable. Everything that varies per run -- the facts, the
        # gate grid, the measured surface, the field values -- lives inside the
        # observation it came from, below.
        parts.append(
            f'<h3>Observations <span class="note">{len(rows)} recorded, '
            "newest first. Open one to see every field that run recorded.</span></h3>"
        )
        for row in reversed(rows):
            ident = row.get("measurement") or row.get("keyset_digest") or ""
            status = row.get("http_status", 0)
            ok = status == 200 and bool(ident)
            cls = "ok" if ok else "bad"
            note = row.get("note") or ""
            src = row.get("source_url") or ""
            parts.append("<details class=\"obs\">")
            parts.append(
                '<summary>'
                f'<span class="when">{html.escape(row.get("observed_at", "")[:19])}</span>'
                f'<span class="{cls}">http {html.escape(str(status))}</span>'
                f'<span class="ident">{html.escape(ident[:24]) if ident else "no identity"}</span>'
                '<span class="end">'
                + (f'<span class="chip chip-red">{html.escape(note)}</span>' if note else "")
                + "</span></summary>"
            )
            parts.append('<div class="body">')

            # The run's verification state, for this observation.
            parts.append('<div class="facts">' + "".join(_row_facts(row)) + "</div>")

            # The row's own re-fetch affordance, stated once. It used to be a
            # table cell; when that table became a field dump the cell was
            # dropped, which silently removed the one thing a reader needs to
            # check a row. `_recheck_link` states the endpoint and either a
            # re-fetch link or the single-use-challenge reason it cannot work.
            if src:
                parts.append(
                    '<p class="note">source <span class="mono">'
                    f"{html.escape(strip_query(src))}</span> {_recheck_link(src)}</p>"
                )

            # The gate grid and the measured surface, both computed from *this*
            # row. They used to be built from `usable[-1]` at the vendor level,
            # so a source with several observations showed one run's checks and
            # silently dropped the rest.
            parts.append("<h4>Checks</h4>")
            parts.extend(_gate_parts(row))

            surface = _surface_row(row)
            parts.append(
                '<h4>Measured surface '
                f'<span class="note">{len(surface)} of {len(SURFACE_FIELDS)} '
                "fields published</span></h4>"
            )
            if surface:
                parts.append('<table class="kv">')
                for name, value in surface:
                    parts.append(
                        f'<tr><td class="k">{html.escape(name)}</td>'
                        f'<td class="v">{html.escape(str(value))}</td></tr>'
                    )
                parts.append("</table>")
            else:
                parts.append(
                    '<p class="empty">Nothing readable was published in this '
                    "observation.</p>"
                )

            parts.append('<h4>Every field recorded</h4>')
            parts.append("<table>")
            for key in sorted(row):
                value = row.get(key)
                if key == "source_url":
                    # The endpoint is already stated above with its re-fetch
                    # affordance. Printing the raw URL here would put the
                    # per-run nonce back on the page, which the log strips on
                    # purpose.
                    continue
                if key == "workload_digests" and value:
                    # A 15-entry JSON blob wrapped in a table cell overflows the
                    # row and stops being readable. It gets the full-width
                    # block the row already had.
                    parts.append("</table>")
                    parts.append(
                        '<p class="note">workload digests</p>'
                        f'<pre class="blob">{html.escape(str(value))}</pre>'
                    )
                    parts.append("<table>")
                    continue
                if value is None or value == "":
                    value = "&mdash;"
                    vcls = "v faint"
                else:
                    value = html.escape(str(value))
                    vcls = "v"
                parts.append(
                    f'<tr><td class="k">{html.escape(key)}</td>'
                    f'<td class="{vcls}">{value}</td></tr>'
                )
            parts.append("</table>")
            parts.append("</div></details>")
        parts.append(
            '<p class="empty">To check a row: open <em>re-fetch</em>, save the response, '
            "and compare its SHA-256 with the hash above.</p>"
        )

        # --- what changed across this source's observations ---
        # This is the one block that is genuinely about the series rather than
        # any single run, so it stays at the vendor level.
        changes = find_changes(rows)
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
        parts.append("</section>")

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
