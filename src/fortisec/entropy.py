"""Entropy helpers for detecting random-looking strings."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class EntropyResult:
    """Detailed entropy analysis for a string."""

    entropy: float
    score: float
    high_entropy: bool


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy in bits per character.

    Args:
        text: Text to evaluate.

    Returns:
        Shannon entropy value. Empty or non-string inputs return 0.0.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> round(shannon_entropy("aaaa"), 2)
        0.0
    """
    if not isinstance(text, str) or not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def entropy_score(text: str) -> float:
    """Return entropy as a normalized 0.0 to 1.0 score.

    Args:
        text: Text to evaluate.

    Returns:
        Normalized score where 1.0 is very random-looking.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> entropy_score("")
        0.0
    """
    entropy = shannon_entropy(text)
    if not isinstance(text, str) or not text:
        return 0.0
    max_entropy = math.log2(min(len(set(text)), 94) or 1)
    if max_entropy <= 0:
        return 0.0
    return min(entropy / max_entropy, 1.0)


def is_high_entropy(text: str, *, threshold: float = 3.5, min_length: int = 20) -> bool:
    """Detect whether text looks like a random token or secret.

    Args:
        text: Text to evaluate.
        threshold: Minimum Shannon entropy required.
        min_length: Minimum text length required.

    Returns:
        True when the text is long and random-looking, otherwise False.

    Raises:
        This function does not raise for invalid input.

    Examples:
        >>> is_high_entropy("abc")
        False
    """
    if not isinstance(text, str) or len(text) < min_length:
        return False
    return shannon_entropy(text) >= threshold

