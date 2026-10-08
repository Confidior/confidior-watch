"""One clock, one format. The tests that keep the time series reproducible."""

from __future__ import annotations

import ast
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from watch.clock import utc_now, utc_now_iso  # noqa: E402

WATCH = Path(__file__).resolve().parents[1] / "watch"
CLOCK_MODULE = WATCH / "clock.py"


def test_utc_now_is_aware_and_utc():
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timezone.utc.utcoffset(None)


def test_utc_now_iso_round_trips_as_a_utc_instant():
    parsed = datetime.fromisoformat(utc_now_iso())
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_timestamps_sort_lexicographically_and_chronologically_together():
    """The log is append-only and human-greppable. Sorting must agree."""
    stamps = ["2026-10-08T19:57:48+00:00", "2026-10-09T06:17:02+00:00"]
    assert sorted(stamps) == [stamps[0], stamps[1]]


def _direct_clock_reads(path: Path) -> list[str]:
    """Every `datetime.now()` / `utcnow()` call in *path*, as source lines."""
    found: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        func = node.func
        if func.attr not in ("now", "utcnow"):
            continue
        base = func.value
        name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
        if name == "datetime":
            found.append(f"{path}:{node.lineno}: {func.attr}()")
    return found


def test_only_the_clock_module_reads_the_wall_clock():
    """A second clock read is a second format, eventually.

    This log is append-only and hash-anchored: a format change is unrecoverable,
    because the bytes are already in the transparency log. The defect is silent
    otherwise, which is exactly why it is asserted here.
    """
    offenders: list[str] = []
    for path in sorted(WATCH.glob("*.py")):
        if path == CLOCK_MODULE:
            continue
        offenders.extend(_direct_clock_reads(path))
    assert offenders == [], "wall-clock read outside watch/clock.py:\n" + "\n".join(offenders)


def test_every_record_carries_a_utc_timestamp():
    """No observation may be written with a naive or absent timestamp."""
    from watch.collector import collect, heartbeat
    from watch.sources import Source, parse_dstack

    src = Source(vendor="v", url="https://x", parse=parse_dstack)
    (obs,) = collect([src], fetcher=lambda u: (200, b"{}"))
    for record in (obs, heartbeat([obs])):
        parsed = datetime.fromisoformat(record.observed_at)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset().total_seconds() == 0
