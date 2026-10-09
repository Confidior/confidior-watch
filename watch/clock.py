"""One source of wall-clock time for the watch repo.

Every timestamp written to the observation log comes from here.

**Why a module and not ``datetime.now()`` at each site.** This repo's entire
product is a trustworthy time series. A naive local timestamp on a machine in any
timezone but UTC records the wrong instant, and the resulting log is not
comparable with itself. Worse, a second clock read is eventually a second format,
and a format change in a log that is append-only and hash-anchored is
unrecoverable: the bytes are already in the transparency log.

The format matches the engine's (``isoformat()`` on a UTC-aware value) so that
log lines and engine records sort together and compare directly.

**On clock trust.** These timestamps come from the host's wall clock. They are
honest about what they are: the time the crawler observed the response. They are
not independently attested, and they should not be read as a trusted time source.
When this runs under GitHub Actions the runner's clock is used; when it runs
locally, the local clock is used. A reader verifying an anchor is checking that
*this digest existed in the log at this point in the log's history*, which the
Rekor inclusion proof establishes independently of this timestamp.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """The current instant, timezone-aware and in UTC."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """The current instant in the log's stored format."""
    return utc_now().replace(microsecond=0).isoformat()
