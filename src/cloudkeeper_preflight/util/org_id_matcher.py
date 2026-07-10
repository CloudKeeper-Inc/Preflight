from __future__ import annotations

import json
import re
from typing import Iterable


class OrgIdMatcher:
    """Detects references to an AWS Organization, its OUs, or org-scoped condition keys
    inside arbitrary text or JSON-able policy documents.
    """

    _ORG_ID_REGEX = re.compile(r"\bo-[a-z0-9]{10,32}\b")
    _OU_ID_REGEX = re.compile(r"\bou-[a-z0-9]{4,32}-[a-z0-9]{8,32}\b")
    _CONDITION_KEYS = (
        "aws:PrincipalOrgID",
        "aws:PrincipalOrgPaths",
        "aws:ResourceOrgID",
        "aws:ResourceOrgPaths",
    )
    _CONTEXT_RADIUS = 50

    def __init__(self, org_id: str, ou_ids: Iterable[str]):
        self.org_id = org_id
        self.ou_ids = set(ou_ids)
        self.condition_keys = self._CONDITION_KEYS

    def has_match(self, text) -> bool:
        s = self._coerce(text)
        if not s:
            return False
        if self.org_id and self.org_id in s:
            return True
        if self._ORG_ID_REGEX.search(s):
            return True
        if self._OU_ID_REGEX.search(s):
            return True
        for key in self._CONDITION_KEYS:
            if key in s:
                return True
        for ou in self.ou_ids:
            if ou and ou in s:
                return True
        return False

    def find_matches(self, text) -> list[dict]:
        s = self._coerce(text)
        if not s:
            return []
        seen: set[tuple[str, str, int]] = set()
        results: list[dict] = []

        def emit(match_type: str, value: str, start: int, end: int) -> None:
            key = (match_type, value, start)
            if key in seen:
                return
            seen.add(key)
            results.append(
                {
                    "type": match_type,
                    "value": value,
                    "context": self._context(s, start, end),
                }
            )

        for m in self._ORG_ID_REGEX.finditer(s):
            emit("org_id", m.group(0), m.start(), m.end())
        for m in self._OU_ID_REGEX.finditer(s):
            emit("ou_id", m.group(0), m.start(), m.end())
        for key in self._CONDITION_KEYS:
            for start in self._iter_substring_positions(s, key):
                emit("condition_key", key, start, start + len(key))

        return results

    @staticmethod
    def _coerce(text) -> str:
        if text is None:
            return ""
        if isinstance(text, str):
            return text
        try:
            return json.dumps(text, default=str)
        except (TypeError, ValueError):
            return str(text)

    @classmethod
    def _context(cls, s: str, start: int, end: int) -> str:
        lo = max(0, start - cls._CONTEXT_RADIUS)
        hi = min(len(s), end + cls._CONTEXT_RADIUS)
        return s[lo:hi]

    @staticmethod
    def _iter_substring_positions(s: str, needle: str) -> Iterable[int]:
        if not needle:
            return
        idx = 0
        while True:
            found = s.find(needle, idx)
            if found == -1:
                return
            yield found
            idx = found + 1
