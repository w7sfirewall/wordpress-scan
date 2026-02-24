"""Data models for scanner results."""

from dataclasses import dataclass
from typing import Literal

MethodType = Literal["POST", "PUT", "PATCH"]
FindingKind = Literal["wp_http_api", "rest_route", "admin_post", "ajax"]
ConfidenceLevel = Literal["high", "medium"]


@dataclass(frozen=True)
class Finding:
    """Structured finding model."""

    file: str
    line: int
    method: MethodType
    kind: FindingKind
    confidence: ConfidenceLevel
    url: str

    @property
    def dedupe_key(self) -> tuple[str, int, MethodType, str]:
        """Return key used for deduplication."""
        return (self.file, self.line, self.method, self.url)

    def to_dict(self) -> dict[str, str | int]:
        """Serialize finding to dictionary output."""
        return {
            "file": self.file,
            "line": self.line,
            "method": self.method,
            "kind": self.kind,
            "confidence": self.confidence,
            "url": self.url,
        }
