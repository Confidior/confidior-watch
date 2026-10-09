# Observation data licence

The observation log (`observations.jsonl`) is released under **CC0 1.0 Universal**
(public domain dedication).

To the extent possible under law, all copyright and related rights to the
observation data in this repository are waived.

You may copy, modify, distribute and use the data for any purpose, including
commercially, without asking permission and without attribution.

## Why this is deliberate

Anyone can run a cron job against the same public endpoints, so the observation
carries little value on its own. What is genuinely hard is the judgment applied
to it: which change matters for which threat model, whether it moves a buyer
below their policy threshold, and what evidence an auditor will accept.

That judgment is not in this repository and is not the point of it. Keeping the
observation layer maximally open is what makes the neutrality claim checkable
rather than a promise.

## What this does not cover

- The **code** in this repository is Apache-2.0. See `LICENSE.md`.
- The **underlying evidence** remains whatever the publishing vendors made it.
  This repository records what they published and when; it claims no rights over
  their material.
- A vendor's trademarks, names and marks remain theirs.
