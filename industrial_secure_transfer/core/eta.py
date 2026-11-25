"""
core/eta.py
Rolling 15-30s verified throughput ETA calculator (UI-06, PERF-01):
- Tracks verified bytes completed within a sliding time window (default 20s, configurable 15-30s).
- Returns "Unavailable" whenever transfer is paused, stalled, disconnected, or has insufficient samples.
- Computes rolling rate (bytes/sec) and formatted human-readable ETA only from verified progress.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Optional, Tuple


@dataclass(frozen=True)
class ETASnapshot:
    verified_bytes: int
    total_bytes: int
    rolling_rate_bps: float
    eta_seconds: Optional[float]
    eta_display: str
    progress_fraction: float


class RollingETACalculator:
    """
    Calculates transfer throughput and ETA over a rolling 15-30 second window of
    verified chunk completions.
    """

    def __init__(
        self,
        total_bytes: int,
        *,
        window_seconds: float = 20.0,
        stall_threshold_seconds: float = 10.0,
        min_samples: int = 2,
        min_elapsed_seconds: float = 0.25,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not (15.0 <= window_seconds <= 30.0):
            raise ValueError("Rolling ETA window_seconds must be between 15.0 and 30.0 seconds.")
        self._total_bytes = max(0, total_bytes)
        self._window_seconds = window_seconds
        self._stall_threshold = max(1.0, stall_threshold_seconds)
        self._min_samples = max(2, min_samples)
        self._min_elapsed = max(0.01, min_elapsed_seconds)
        self._clock = clock

        self._verified_bytes = 0
        self._paused = False
        self._disconnected = False
        # Deque of (timestamp, cumulative_verified_bytes)
        self._samples: Deque[Tuple[float, int]] = deque()

    @property
    def verified_bytes(self) -> int:
        return self._verified_bytes

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    def start(self) -> None:
        """Records the baseline sample at t=now with current verified_bytes."""
        now = self._clock()
        self._paused = False
        self._disconnected = False
        self._samples.clear()
        self._samples.append((now, self._verified_bytes))

    def record_verified_bytes(self, delta_bytes: int) -> None:
        """Records newly verified bytes (after read-back hash confirmation)."""
        if delta_bytes < 0:
            raise ValueError("Verified delta_bytes cannot be negative.")
        now = self._clock()
        self._verified_bytes = min(self._total_bytes, self._verified_bytes + delta_bytes)
        self._samples.append((now, self._verified_bytes))
        self._prune_old_samples(now)

    def set_paused(self, paused: bool) -> None:
        self._paused = paused
        if paused:
            self._samples.clear()
        else:
            self._samples.append((self._clock(), self._verified_bytes))

    def set_disconnected(self, disconnected: bool) -> None:
        self._disconnected = disconnected
        if disconnected:
            self._samples.clear()

    def _prune_old_samples(self, now: float) -> None:
        cutoff = now - self._window_seconds
        while len(self._samples) > 2 and self._samples[0][0] < cutoff:
            self._samples.popleft()

    @staticmethod
    def format_seconds(seconds: float) -> str:
        secs = max(0, int(round(seconds)))
        hours, rem = divmod(secs, 3600)
        minutes, s = divmod(rem, 60)
        if hours > 0:
            return f"{hours}h {minutes:02d}m {s:02d}s"
        if minutes > 0:
            return f"{minutes}m {s:02d}s"
        return f"{s}s"

    def snapshot(self, *, stage_completed: bool = False) -> ETASnapshot:
        """
        Computes the current rolling throughput and ETA.
        Never claims 1.0 (100%) until `stage_completed=True` (UI-05/Section 17).
        Returns "Unavailable" when paused, disconnected, stalled, or with insufficient samples (UI-06).
        """
        now = self._clock()
        self._prune_old_samples(now)

        if self._total_bytes == 0:
            frac = 1.0 if stage_completed else 0.0
            return ETASnapshot(0, 0, 0.0, 0.0 if stage_completed else None, "0s" if stage_completed else "Unavailable", frac)

        raw_fraction = self._verified_bytes / self._total_bytes
        if stage_completed and self._verified_bytes >= self._total_bytes:
            progress_fraction = 1.0
        else:
            # Cap at 0.999 until the relevant completion condition (e.g. receipt or manifest verify) is reached
            progress_fraction = min(0.999, raw_fraction)

        if stage_completed and self._verified_bytes >= self._total_bytes:
            return ETASnapshot(
                verified_bytes=self._verified_bytes,
                total_bytes=self._total_bytes,
                rolling_rate_bps=0.0,
                eta_seconds=0.0,
                eta_display="0s",
                progress_fraction=1.0,
            )

        if self._paused or self._disconnected or len(self._samples) < self._min_samples:
            return ETASnapshot(
                verified_bytes=self._verified_bytes,
                total_bytes=self._total_bytes,
                rolling_rate_bps=0.0,
                eta_seconds=None,
                eta_display="Unavailable",
                progress_fraction=progress_fraction,
            )

        last_t, last_b = self._samples[-1]
        if (now - last_t) > self._stall_threshold:
            # Stalled: no verified progress within stall threshold
            return ETASnapshot(
                verified_bytes=self._verified_bytes,
                total_bytes=self._total_bytes,
                rolling_rate_bps=0.0,
                eta_seconds=None,
                eta_display="Unavailable",
                progress_fraction=progress_fraction,
            )

        first_t, first_b = self._samples[0]
        dt = last_t - first_t
        db = last_b - first_b
        if dt < self._min_elapsed or db <= 0:
            return ETASnapshot(
                verified_bytes=self._verified_bytes,
                total_bytes=self._total_bytes,
                rolling_rate_bps=0.0,
                eta_seconds=None,
                eta_display="Unavailable",
                progress_fraction=progress_fraction,
            )

        rate = db / dt
        remaining = max(0, self._total_bytes - self._verified_bytes)
        eta_secs = remaining / rate
        return ETASnapshot(
            verified_bytes=self._verified_bytes,
            total_bytes=self._total_bytes,
            rolling_rate_bps=rate,
            eta_seconds=eta_secs,
            eta_display=self.format_seconds(eta_secs),
            progress_fraction=progress_fraction,
        )
