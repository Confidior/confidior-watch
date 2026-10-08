# confidior-watch

A scheduled crawl that records what vendors publish about their own attestation
evidence, over time, so that point-in-time observations become a time series.

A single capture is an anecdote. A thousand captures is a history. This is the
mechanism that turns one into the other.

**This is not a service.** No accounts, no alerts, no uptime commitment. It
observes; it does not grade. Its worst failure mode is a gap in a timeline, and
for an evidence archive silence never reads as a claim.

## Why this exists

Attestation is point-in-time. When you verify a quote you learn *right now, this
hardware runs this measured code*. You learn nothing about yesterday.

Artifact identity is not time-limited — "the image running is the image whose
digest we derive from its bytes" stays true indefinitely. What decays is the
separate claim *"this is what is running now."*

A better verification does not fix that. Repetition does. So this crawls
publicly-published evidence on a schedule and keeps every observation.

## What it produces

| Artifact | What it is |
|---|---|
| `observations.jsonl` | Append-only. One line per observation — timestamp, vendor, identity fields, source URL, HTTP status, SHA-256 of the raw response |
| `docs/index.html` | One page. Per vendor: the timeline, every change with its date, and the headline number — *unchanged since X* |
| A daily Rekor anchor | The day's digest submitted to Sigstore, so the history is tamper-evident to a stranger |

## Design rules

These are load-bearing, and each has a test enforcing it.

- **A dead source is a finding, not a failure.** A non-200 is recorded as an
  observation with its status. "No observations since DATE" is honest and
  interesting; a vendor that stopped publishing is news.
- **A parser never raises.** A shape change produces a note. An aborted run is a
  gap in the timeline, and the timeline is the asset.
- **Failures surface themselves.** If no source returns readable evidence, the
  job opens an issue on itself. One bad week is normal; zero readable evidence
  means something needs a human.
- **Depth over breadth.** Three sources, deliberately. Five to eight with
  unbroken history proves continuity; sixty with patchy history proves nothing.
  Every addition costs adapter rot forever.
- **The worst failure is visible.** A heartbeat record is written every run, so a
  gap means "the job stopped" rather than "nothing happened."
- **Anchoring fails soft.** An unanchored day is still a day of history. Never
  lose an observation because the transparency log was unreachable.

## Sources

Each parser was written against a response captured live on 2026-10-09. None was
written against documentation, because for these endpoints there is none.

| Vendor | Endpoint | Platform | Shape |
|---|---|---|---|
| RedPill | `api.redpill.ai/v1/attestation/report` | Intel TDX | dstack `aci/1` |
| Phala | `inference.phala.com/v1/aci/attestation` | Intel TDX | dstack `aci/1` |
| PPQ | `api.ppq.ai/attestation` | AWS Nitro | `nsm-cose-sign1` |

### What identity means here

The log watches the fields that change when a deployment changes: `compose-hash`,
`os-image-hash`, `app-id`, `mr-kms`, `keyset_digest`, `repo_commit`, `cert_spki_sha256`.

Two things are deliberately excluded from identity:

- **`instance-id`** — changes on every restart. Recording it would be constant
  false drift.
- **`response_sha256`** — changes whenever any byte of the response moves,
  including fields we do not care about. It is recorded in the log so a third
  party can re-fetch and compare; it is not identity.

### Deliberately excluded sources

Recorded so nobody re-adds them by accident. Each is a factual observation about
publication posture, not a judgement.

| Vendor | Status on 2026-10-09 |
|---|---|
| Tinfoil | `api.tinfoil.sh/v1/attestation/report` exists but rejects unencrypted bodies (HTTP 426, `EHBP_REQUIRED`). Reading it means implementing their client-side encryption — authentication in effect |
| NEAR AI | `cloud-api.near.ai/v1/attestation/report` returns 401. Keyed |
| Chutes | `api.chutes.ai/v1/attestation` returns 429 under plain GET |
| Venice, Maple, NanoGPT, Privatemode | No public attestation endpoint located at the obvious paths |

Several of these may publish evidence through their own authenticated tooling.
That is a different claim from publishing it openly, and only the second is
observable by a neutral third party.

## Running it

```sh
pip install -r requirements.txt
python -m watch.collector --log observations.jsonl --anchor
python -m watch.render --log observations.jsonl --out docs/index.html
python -m pytest tests/ -q
```

`--dry-run` prints without writing.

## What to look at first

The first genuinely interesting finding is already in the log. RedPill and Phala
return the **same** `workload_keyset_digest` and the **same** `compose-hash`.
RedPill's payload additionally embeds Phala domains and the dstack
`private-ai-gateway` compose. Two providers, one measured workload.

That is the reseller-attribution problem, visible from public endpoints without
asking anyone's permission — and it is exactly the kind of thing a
per-provider continuity log surfaces and a pricing table cannot.

## Licence

- **Code:** Apache-2.0 (`LICENSE.md`)
- **Observation data (`observations.jsonl`):** CC0 — public domain. Reuse freely,
  no permission needed, no attribution required.

The data is deliberately maximally permissive. Anyone can cron the same endpoints;
the observation is worth little on its own. What is hard is the judgment applied
to it, and that is not this repository's job.

## Provenance

`watch/rekor_vendored.py` is a frozen copy of the anchoring path from
`confidior-engine` (Apache-2.0), recorded at the top of that file. It is vendored
rather than imported on purpose: the clock must not depend on anything that moves.
