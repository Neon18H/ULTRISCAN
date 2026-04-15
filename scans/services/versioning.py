from __future__ import annotations

import logging
import re
from itertools import zip_longest

logger = logging.getLogger(__name__)

_VERSION_TOKEN_RE = re.compile(r"[vV]?\d+(?:[._-]\d+)*(?:p\d+)?")
_PATCH_SUFFIX_RE = re.compile(r"^(?P<base>\d+(?:\.\d+)*)p(?P<patch>\d+)$", re.IGNORECASE)


def normalize_version(raw_version: str) -> str:
    """Extract a best-effort normalized version token from noisy scanner output."""
    raw_value = (raw_version or '').strip()
    if not raw_value:
        return ''

    match = _VERSION_TOKEN_RE.search(raw_value)
    if not match:
        return ''

    token = match.group(0).strip().lstrip('vV').replace('_', '.')
    if '-' in token:
        token = token.split('-', 1)[0]

    patch_match = _PATCH_SUFFIX_RE.match(token)
    if patch_match:
        token = f"{patch_match.group('base')}.{patch_match.group('patch')}"

    return token.strip('.- ')


def parse_comparable_version(version_value: str) -> tuple[int, ...] | None:
    """Parse a version string into a tuple of integers for safe comparisons."""
    normalized = normalize_version(version_value)
    if not normalized:
        return None

    numeric_parts = re.findall(r"\d+", normalized)
    if not numeric_parts:
        return None

    return tuple(int(part) for part in numeric_parts)


def compare_versions(current: str, operator: str, expected: str) -> bool:
    current_tuple = parse_comparable_version(current)
    expected_tuple = parse_comparable_version(expected)
    if current_tuple is None or expected_tuple is None:
        logger.warning(
            'Skipping version comparison due to non-normalizable version. current=%r expected=%r operator=%s',
            current,
            expected,
            operator,
        )
        return False

    comparison = _compare_tuples(current_tuple, expected_tuple)
    if operator == '<':
        return comparison < 0
    if operator == '<=':
        return comparison <= 0
    if operator == '>':
        return comparison > 0
    if operator == '>=':
        return comparison >= 0
    if operator == '==':
        return comparison == 0
    return False


def version_in_range(current: str, min_version: str, max_version: str) -> bool:
    current_tuple = parse_comparable_version(current)
    min_tuple = parse_comparable_version(min_version) if min_version else None
    max_tuple = parse_comparable_version(max_version) if max_version else None

    if current_tuple is None:
        logger.warning(
            'Skipping version range check due to non-normalizable current version. current=%r range=%r..%r',
            current,
            min_version,
            max_version,
        )
        return False

    if min_version and min_tuple is None:
        logger.warning('Ignoring invalid rule min_version=%r', min_version)
    if max_version and max_tuple is None:
        logger.warning('Ignoring invalid rule max_version=%r', max_version)

    if min_tuple is not None and _compare_tuples(current_tuple, min_tuple) < 0:
        return False
    if max_tuple is not None and _compare_tuples(current_tuple, max_tuple) > 0:
        return False
    return True


def _compare_tuples(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    for l_value, r_value in zip_longest(left, right, fillvalue=0):
        if l_value < r_value:
            return -1
        if l_value > r_value:
            return 1
    return 0
