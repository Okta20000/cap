"""
Realistic mouse-movement generation for hCaptcha.

hCaptcha's decision engine analyses motionData: Bézier curvature,
acceleration profile, inter-event timing, click distribution.
We generate cubic Bézier paths with variable timing (slower at start
and end, faster in the middle) plus per-sample jitter.
"""
from __future__ import annotations

import math
import random
import time
from typing import Dict, List, Tuple


def _cubic(p0, p1, p2, p3, t):
    mt = 1 - t
    return (
        mt**3 * p0[0] + 3 * mt**2 * t * p1[0] + 3 * mt * t**2 * p2[0] + t**3 * p3[0],
        mt**3 * p0[1] + 3 * mt**2 * t * p1[1] + 3 * mt * t**2 * p2[1] + t**3 * p3[1],
    )


def _timing(t: float) -> float:
    """Acceleration profile: slow → fast → slow."""
    if t < 0.2:
        return 1.6
    if t > 0.8:
        return 1.6
    return 0.85


def generate(
    start: Tuple[int, int],
    end: Tuple[int, int],
    steps: int = 40,
    jitter: float = 2.0,
    seed: int | None = None,
) -> List[Dict[str, float]]:
    """
    Return a motionData `movements` list: [{"x": …, "y": …, "t": …}, …].

    `t` is a millisecond timestamp relative to the first sample.
    """
    rng = random.Random(seed)

    # Bézier control points offset from the straight-line segment
    dx, dy = end[0] - start[0], end[1] - start[1]
    perp = (-dy, dx)
    cp1 = (
        start[0] + dx * 0.3 + perp[0] * rng.uniform(0.05, 0.20),
        start[1] + dy * 0.3 + perp[1] * rng.uniform(0.05, 0.20),
    )
    cp2 = (
        start[0] + dx * 0.7 + perp[0] * rng.uniform(-0.20, -0.05),
        start[1] + dy * 0.7 + perp[1] * rng.uniform(-0.20, -0.05),
    )

    movements: List[Dict[str, float]] = []
    elapsed = 0.0
    for i in range(steps):
        t = i / (steps - 1) if steps > 1 else 0.0
        x, y = _cubic(start, cp1, cp2, end, t)

        # sub-pixel jitter
        x += rng.uniform(-jitter, jitter)
        y += rng.uniform(-jitter, jitter)

        elapsed += 16.0 * _timing(t) + rng.uniform(-2, 2)
        movements.append({"x": round(x, 2), "y": round(y, 2), "t": round(elapsed)})

    return movements


def motion_data(movements: List[Dict[str, float]]) -> Dict:
    """
    Wrap a movements list into the full `motionData` object that
    hCaptcha sends on the wire.
    """
    now_ms = int(time.time() * 1000)
    start = now_ms - int(movements[-1]["t"] if movements else 0) - 200
    return {
        "v": 1,
        "movements": movements,
        "start": start,
        "end": now_ms,
    }