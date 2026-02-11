"""Data models for scanner results."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha1
from typing import Literal

MethodType = Literal["POST", "PUT", "PATCH", "UNKNOWN"]
FindingKind = Literal["wp_http_api", "rest_route", "admin_post", "ajax"]
ConfidenceLevel = Literal["high", "medium"]


@dataclass(frozen=True)
class Finding:
    """Structured finding model."""

    file: str
    line: int
    method: MethodType
    kind: FindingKind
    evidence: str
    confidence: ConfidenceLevel
    url: str | None = None

    @property
    def dedupe_key(self) -> tuple[str, int, MethodType, FindingKind]:
        """Return key used for deduplication."""
        return (self.file, self.line, self.method, self.kind)

    @property
    def id(self) -> str:
        """Return stable finding id based on key fields."""
        payload = f"{self.file}:{self.line}:{self.method}:{self.kind}"
        return sha1(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, str | int | None]:
        """Serialize finding to dictionary output."""
        return {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "method": self.method,
            "kind": self.kind,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "url": self.url,
        }
