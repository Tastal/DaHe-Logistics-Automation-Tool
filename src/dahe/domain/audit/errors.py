from __future__ import annotations


class DomainContractError(ValueError):
    """Raised when a caller violates a pure business contract."""


class SystemEvidenceError(RuntimeError):
    """Raised when infrastructure failure prevents a business decision."""


class StaleEvidenceError(DomainContractError):
    """Raised when a manual action targets evidence that has changed."""

