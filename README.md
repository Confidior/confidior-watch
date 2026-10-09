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
| `observations.jsonl` | Append-only. One line per observation — timestamp, vendor, identity fields, the full extracted surface, source URL, HTTP status, SHA-256 of the raw response |
| `watch/timeline.py` | Analysis over the log: what changed between consecutive observations, which fields count as identity, how long a vendor has been stable |
| A Rekor anchor | The run's log digest submitted to Sigstore, so the history is tamper-evident to a stranger |

There is no page. The log is the published artifact, and a consumer renders it.

## Design rules

These are load-bearing. Most are enforced by a test in `tests/`; the one that
is not is enforced by the workflow instead, and says so below.

- **A dead source is a finding, not a failure.** A non-200 is recorded as an
  observation with its status. "No observations since DATE" is honest and
  interesting; a vendor that stopped publishing is news.
- **A parser never raises.** A shape change produces a note. An aborted run is a
  gap in the timeline, and the timeline is the asset.
- **Failures surface themselves.** If no source returns readable evidence, the
  job opens an issue on itself. One bad week is normal; zero readable evidence
  means something needs a human. This one has no unit test: it is the
  `Open an issue if nothing was readable` step in
  `.github/workflows/observe.yml`, which is where the claim is checkable.
- **Depth over breadth.** Five sources, deliberately. Five to eight with
  unbroken history proves continuity; sixty with patchy history proves nothing.
  Every addition costs adapter rot forever.
- **The worst failure is visible.** A heartbeat record is written every run, so a
  gap means "the job stopped" rather than "nothing happened."
- **Anchoring fails soft.** An unanchored day is still a day of history. Never
  lose an observation because the transparency log was unreachable.

## Sources

Each parser was written against a response captured live on 2026-10-09. None was
written against documentation, because for these endpoints there is none.

| Vendor | Endpoint | Platform | Nonce |
|---|---|---|---|
| RedPill | `api.redpill.ai/v1/attestation/report` | Intel TDX | accepted, echoed |
| Phala | `inference.phala.com/v1/aci/attestation` | Intel TDX | accepted, not echoed |
| PPQ | `api.ppq.ai/attestation` | AWS Nitro | none |
| Tinfoil | `inference.tinfoil.sh/.well-known/tinfoil-attestation` | AMD SEV-SNP | required for the full v3 evidence set |
| Confidential AI | `api.confidential.ai/attestation` | Confidential AI C8S | required; returns 400 without one |

### What identity means here

The log watches the fields that change when a deployment changes: `measurement`,
`tcb_version`, `os_image_hash`, `app_id`, `mr_kms`, `keyset_digest`, `repo_commit`,
`cert_spki_sha256`, and the release and protocol identifiers alongside them. The
full list is `IDENTITY_FIELDS` in `watch/timeline.py`.

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
| Tinfoil (`api.tinfoil.sh/v1/attestation/report`) | Exists but rejects unencrypted bodies (HTTP 426, `EHBP_REQUIRED`). Reading it means implementing their client-side encryption — authentication in effect. Tinfoil is still crawled through its `.well-known` path, above |
| NEAR AI | `cloud-api.near.ai/v1/attestation/report` returns 401 — requires a key |
| Chutes | `api.chutes.ai/v1/attestation` returns 429 under a plain GET |
| Venice, Maple, NanoGPT, Privatemode | No public attestation endpoint found at the obvious paths |

Several of these may publish evidence through their own authenticated tooling.
That is a different claim from publishing it openly, and only the second is
observable by a neutral third party.

## Running it

Dependencies and dev tools are declared in `pyproject.toml` and pinned in
`uv.lock`. This needs [uv](https://docs.astral.sh/uv/):

```sh
uv run python -m watch.collector --log observations.jsonl --anchor
uv run pytest tests/ -q
```

`uv run` creates the virtualenv and installs the locked dependencies on first
use. `--dry-run` prints without writing. The run does not require the engine:
without a `confidior-engine` checkout beside this repo, the signature check
records `engine not importable` and the run still completes (see Provenance).

## What to look at first

The first genuinely interesting finding is already in the log. RedPill and Phala
return the **same** `keyset_digest`, the **same** `os_image_hash`, the same
`tls_binding_domains` (both `api.redpill.ai` and `inference.phala.com` among
them), and both name the same dstack `private-ai-gateway` repository. Two
providers, one measured workload.

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

The **signature** check verifies a quote against the vendor root of trust, and
the verifiers for that live in `confidior-engine`
(`src/ingest/adapters/tdx.py` and `nitro.py`). `watch/checks.py` imports them at
call time if a checkout is reachable — via `CONFIDIOR_ENGINE_PATH`, or a sibling
`confidior-engine` directory. When it is not, the check records
`engine not importable` and the run continues; the log records the gap rather
than hiding it. Everything else — freshness, wire, the nonce and TLS checks —
is done here and needs no engine.

So: clone this repo alone and it runs, records all five sources, and says of each
signature that it could not check it. Put the engine beside it and that column
fills in.
