"""
Password Strength Analyzer
===========================

Pure-Python (stdlib only) library for estimating password strength.

Methodology
-----------
1. Shannon-entropy-based estimate:
   We approximate the "pool size" of possible characters based on which
   character classes are present (lowercase, uppercase, digits, symbols),
   then compute entropy bits as: length * log2(pool_size).
   This is the classic "worst case brute force" entropy estimate used by
   tools like zxcvbn's naive baseline (though not as sophisticated as
   zxcvbn's pattern-matching entropy model).

2. Weakness detection (each reduces confidence / triggers feedback):
   - Common / breached password list match (exact or near-miss via a
     simple edit-distance / substring check against data/common_passwords.txt)
   - Keyboard-walk detection (sequences of adjacent keys on a QWERTY
     keyboard, e.g. "qwerty", "asdfgh", "1qaz2wsx")
   - Repeated character / simple sequence detection (e.g. "aaaa", "1234",
     "abcd", "4321")

3. Verdict:
   The raw entropy estimate is penalized when weaknesses are detected,
   producing a final score that maps to one of five verdicts:
   very weak, weak, moderate, strong, very strong.
"""

from __future__ import annotations

import math
import os
import re
import string
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_COMMON_PASSWORDS_PATH = os.path.join(_DATA_DIR, "common_passwords.txt")


def _load_common_passwords(path: str = _COMMON_PASSWORDS_PATH) -> List[str]:
    """Load the bundled common-password list. Returns an empty list if the
    file cannot be found (analyzer still works, just without this check)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except OSError:
        return []


COMMON_PASSWORDS = _load_common_passwords()
_COMMON_PASSWORDS_SET = set(COMMON_PASSWORDS)


# ---------------------------------------------------------------------------
# Keyboard-walk detection
# ---------------------------------------------------------------------------

# QWERTY keyboard rows, used to detect "keyboard walk" patterns such as
# "qwerty", "asdfgh", "zxcvbn", including shifted/adjacent runs.
_KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

_MIN_WALK_LEN = 4


def _build_adjacency():
    """Build a dict mapping each key to the set of keys horizontally
    adjacent to it (left/right on the same row)."""
    adjacency = {}
    for row in _KEYBOARD_ROWS:
        for i, ch in enumerate(row):
            neighbors = set()
            if i > 0:
                neighbors.add(row[i - 1])
            if i < len(row) - 1:
                neighbors.add(row[i + 1])
            adjacency[ch] = neighbors
    return adjacency


_ADJACENCY = _build_adjacency()


def find_keyboard_walks(password: str, min_len: int = _MIN_WALK_LEN) -> List[str]:
    """Return substrings of `password` (lowercased) of length >= min_len
    that form a contiguous run of horizontally-adjacent keys on a QWERTY
    keyboard (walking left-to-right or right-to-left)."""
    lowered = password.lower()
    walks = []
    n = len(lowered)
    i = 0
    while i < n:
        run_len = 1
        j = i
        while j + 1 < n and lowered[j + 1] in _ADJACENCY.get(lowered[j], set()):
            run_len += 1
            j += 1
        if run_len >= min_len:
            walks.append(lowered[i:j + 1])
        i = j + 1 if j > i else i + 1
    return walks


# ---------------------------------------------------------------------------
# Repeated-character / simple-sequence detection
# ---------------------------------------------------------------------------

_MIN_REPEAT_LEN = 4
_MIN_SEQUENCE_LEN = 4


def find_repeated_chars(password: str, min_len: int = _MIN_REPEAT_LEN) -> List[str]:
    """Detect runs of the same character repeated `min_len` or more times,
    e.g. 'aaaa', '1111'."""
    matches = []
    for m in re.finditer(r"(.)\1{" + str(min_len - 1) + r",}", password):
        matches.append(m.group(0))
    return matches


def find_simple_sequences(password: str, min_len: int = _MIN_SEQUENCE_LEN) -> List[str]:
    """Detect ascending or descending runs of consecutive characters by
    ordinal value, e.g. '1234', 'abcd', '4321', 'dcba'."""
    sequences = []
    n = len(password)
    i = 0
    while i < n - 1:
        # ascending run
        j = i
        while j + 1 < n and ord(password[j + 1]) - ord(password[j]) == 1:
            j += 1
        if j - i + 1 >= min_len:
            sequences.append(password[i:j + 1])
            i = j
            continue
        # descending run
        j = i
        while j + 1 < n and ord(password[j + 1]) - ord(password[j]) == -1:
            j += 1
        if j - i + 1 >= min_len:
            sequences.append(password[i:j + 1])
            i = j
            continue
        i += 1
    return sequences


# ---------------------------------------------------------------------------
# Common password / near-miss detection
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Standard edit distance (insert/delete/substitute), used for
    near-miss matching against the common password list."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                prev[j] + 1,       # deletion
                curr[j - 1] + 1,   # insertion
                prev[j - 1] + cost # substitution
            )
        prev = curr
    return prev[-1]


def _strip_trailing_digits_and_symbols(s: str) -> str:
    """Strip common trailing decoration like '123', '!', '2024' so that
    'password123!' reduces to 'password' for matching purposes."""
    return re.sub(r"[\d\W_]+$", "", s)


def find_common_password_match(password: str, common_set=_COMMON_PASSWORDS_SET):
    """Check for exact or near-miss matches against the common password
    list. Returns a tuple (matched_entry, kind) where kind is 'exact',
    'near' (small edit distance or stripped-suffix match), or None if no
    match was found."""
    lowered = password.lower()
    if not lowered:
        return None

    if lowered in common_set:
        return (lowered, "exact")

    stripped = _strip_trailing_digits_and_symbols(lowered)
    if stripped and stripped in common_set:
        return (stripped, "near")

    # Near-miss: small edit distance to a common password of similar length.
    # Only check against entries within +/-2 length to keep this fast and
    # to avoid false positives against very different-length passwords.
    for entry in common_set:
        if abs(len(entry) - len(lowered)) > 2:
            continue
        if len(entry) < 4:
            # too short to safely fuzzy-match without false positives
            if entry == lowered:
                return (entry, "exact")
            continue
        max_dist = 1 if len(entry) <= 6 else 2
        if _levenshtein(lowered, entry) <= max_dist:
            return (entry, "near")

    return None


# ---------------------------------------------------------------------------
# Entropy estimate
# ---------------------------------------------------------------------------

@dataclass
class CharacterPools:
    lowercase: bool = False
    uppercase: bool = False
    digits: bool = False
    symbols: bool = False

    def pool_size(self) -> int:
        size = 0
        if self.lowercase:
            size += 26
        if self.uppercase:
            size += 26
        if self.digits:
            size += 10
        if self.symbols:
            # Printable ASCII symbols (roughly). This is an approximation
            # used purely for entropy estimation.
            size += 33
        return size

    def class_count(self) -> int:
        return sum([self.lowercase, self.uppercase, self.digits, self.symbols])


def detect_character_pools(password: str) -> CharacterPools:
    pools = CharacterPools()
    for ch in password:
        if ch in string.ascii_lowercase:
            pools.lowercase = True
        elif ch in string.ascii_uppercase:
            pools.uppercase = True
        elif ch in string.digits:
            pools.digits = True
        elif not ch.isspace():
            pools.symbols = True
    return pools


def estimate_entropy_bits(password: str) -> float:
    """Shannon-entropy-style estimate: length * log2(pool size), where the
    pool size is derived from which character classes are present.

    An empty password has zero entropy by definition.
    """
    if not password:
        return 0.0
    pools = detect_character_pools(password)
    pool_size = pools.pool_size()
    if pool_size <= 0:
        return 0.0
    return len(password) * math.log2(pool_size)


# ---------------------------------------------------------------------------
# Full analysis
# ---------------------------------------------------------------------------

VERDICTS = ["very weak", "weak", "moderate", "strong", "very strong"]


@dataclass
class AnalysisResult:
    password_length: int
    entropy_bits: float
    score: float
    verdict: str
    feedback: List[str] = field(default_factory=list)
    is_common_password: bool = False
    has_keyboard_walk: bool = False
    has_repeated_chars: bool = False
    has_simple_sequence: bool = False


def analyze_password(password: str) -> AnalysisResult:
    feedback: List[str] = []

    length = len(password)
    entropy = estimate_entropy_bits(password)
    pools = detect_character_pools(password)

    if length == 0:
        return AnalysisResult(
            password_length=0,
            entropy_bits=0.0,
            score=0.0,
            verdict="very weak",
            feedback=["password is empty"],
        )

    # --- length feedback ---
    if length < 8:
        feedback.append("too short (use at least 12 characters)")
    elif length < 12:
        feedback.append("consider using at least 12 characters for better security")

    # --- character class diversity feedback ---
    if not pools.lowercase:
        feedback.append("add lowercase letters")
    if not pools.uppercase:
        feedback.append("add uppercase letters")
    if not pools.digits:
        feedback.append("add digits")
    if not pools.symbols:
        feedback.append("add symbols")

    # --- weakness detection ---
    common_match = find_common_password_match(password)
    is_common = common_match is not None
    if is_common:
        matched_entry, kind = common_match
        if kind == "exact":
            feedback.append("found in common password list")
        else:
            feedback.append(
                f"too similar to a common password ('{matched_entry}')"
            )

    keyboard_walks = find_keyboard_walks(password)
    has_walk = len(keyboard_walks) > 0
    if has_walk:
        feedback.append(
            "contains a keyboard-walk pattern (e.g. " + ", ".join(keyboard_walks) + ")"
        )

    repeated = find_repeated_chars(password)
    has_repeated = len(repeated) > 0
    if has_repeated:
        feedback.append(
            "contains repeated characters (e.g. " + ", ".join(repeated) + ")"
        )

    sequences = find_simple_sequences(password)
    has_sequence = len(sequences) > 0
    if has_sequence:
        feedback.append(
            "contains a simple sequence (e.g. " + ", ".join(sequences) + ")"
        )

    # --- scoring ---
    # Start from the entropy estimate (bits), then apply multiplicative
    # penalties for each detected weakness. This keeps the score
    # monotonic with entropy while still meaningfully punishing
    # well-known weak patterns.
    score = entropy

    if is_common:
        score *= 0.05  # a bundled-common password should score near zero
    if has_walk:
        score *= 0.5
    if has_repeated:
        score *= 0.6
    if has_sequence:
        score *= 0.6

    verdict = _score_to_verdict(score)

    if not feedback:
        feedback.append("no significant weaknesses detected")

    return AnalysisResult(
        password_length=length,
        entropy_bits=round(entropy, 2),
        score=round(score, 2),
        verdict=verdict,
        feedback=feedback,
        is_common_password=is_common,
        has_keyboard_walk=has_walk,
        has_repeated_chars=has_repeated,
        has_simple_sequence=has_sequence,
    )


def _score_to_verdict(score: float) -> str:
    """Map a penalized-entropy score (bits) to a human verdict.

    Thresholds (bits):
      < 28   -> very weak
      < 36   -> weak
      < 60   -> moderate
      < 80   -> strong
      >= 80  -> very strong

    These thresholds loosely follow common entropy-based guidance (e.g.
    NIST / various strength-meter conventions) where ~28 bits is trivially
    crackable and 80+ bits is considered very strong for offline attacks.
    """
    if score < 28:
        return "very weak"
    if score < 36:
        return "weak"
    if score < 60:
        return "moderate"
    if score < 80:
        return "strong"
    return "very strong"


def verdict_rank(verdict: str) -> int:
    """Return the ordinal rank of a verdict (higher = stronger)."""
    return VERDICTS.index(verdict)
