"""Offline Chengfeng connector contracts.

Loop 5 exposes only a frozen, synthetic read contract. Import concrete
connector pieces from their defining modules so adding a later process adapter
does not silently widen this package's public surface.
"""

from dahe.adapters.chengfeng.manifest import (
    FixtureVerificationReport,
    FrozenContractManifest,
    FrozenRequest,
    FrozenResponse,
    ManifestValidationError,
)
from dahe.adapters.chengfeng.policy import (
    AuthorizedRequest,
    ReadOnlyRequestFirewall,
    ReadRequest,
    RequestDeniedError,
)

__all__ = [
    "AuthorizedRequest",
    "FixtureVerificationReport",
    "FrozenContractManifest",
    "FrozenRequest",
    "FrozenResponse",
    "ManifestValidationError",
    "ReadOnlyRequestFirewall",
    "ReadRequest",
    "RequestDeniedError",
]
