"""Response fingerprint helpers for deduplication and noise filtering."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from core.utils import extract_title, sha256_text


@dataclass(slots=True)
class BodyFingerprint:
    status_code: int
    size: int
    words: int
    lines: int
    sha256: str
    title: str | None
    content_type: str | None

    def signature(self) -> tuple[int, int, int, int, str]:
        return (self.status_code, self.size, self.words, self.lines, self.sha256)


def fingerprint_body(body: str | bytes, status_code: int = 200, content_type: str | None = None) -> BodyFingerprint:
    text = body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else body
    raw = body if isinstance(body, bytes) else body.encode("utf-8", errors="ignore")
    return BodyFingerprint(
        status_code=status_code,
        size=len(raw),
        words=len(text.split()),
        lines=text.count("\n") + (1 if text else 0),
        sha256=sha256_text(raw),
        title=extract_title(text),
        content_type=content_type,
    )


def similarity(left: str | bytes | None, right: str | bytes | None) -> float:
    left_text = left.decode("utf-8", errors="ignore") if isinstance(left, bytes) else left or ""
    right_text = right.decode("utf-8", errors="ignore") if isinstance(right, bytes) else right or ""
    if not left_text and not right_text:
        return 1.0
    return SequenceMatcher(None, left_text, right_text).ratio()


def fingerprints_equal(left: BodyFingerprint, right: BodyFingerprint) -> bool:
    return left.signature() == right.signature()
