"""Wilson score intervals, with optional sampling weights."""

import math

Z95 = 1.959964


def wilson(p, n, z=Z95):
    """Wilson score interval (lo, hi) for proportion ``p`` observed on ``n`` trials.

    ``n`` may be fractional (the effective sample size of a weighted sample).
    With no trials the interval is the uninformative (0, 1).
    """
    if n <= 0:
        return 0.0, 1.0
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def effective_n(weights):
    """Kish effective sample size of a weighted sample."""
    total = sum(weights)
    squares = sum(w * w for w in weights)
    return (total * total / squares) if squares else 0.0


def rate(numerator_weights, denominator_weights):
    """``{"value", "lo", "hi", "n"}`` for a weighted proportion.

    ``numerator_weights`` are the weights of the units counted as successes,
    ``denominator_weights`` those of every unit at risk (successes included).
    With unit weights this is the ordinary Wilson interval; otherwise the
    point estimate is weight-corrected and the interval uses the Kish
    effective sample size. ``value`` is None when nothing is at risk.
    """
    denominator = sum(denominator_weights)
    if not denominator_weights or denominator <= 0:
        return {"value": None, "lo": None, "hi": None, "n": 0}
    p = sum(numerator_weights) / denominator
    n = effective_n(denominator_weights)
    lo, hi = wilson(p, n)
    return {"value": p, "lo": lo, "hi": hi, "n": len(denominator_weights)}
