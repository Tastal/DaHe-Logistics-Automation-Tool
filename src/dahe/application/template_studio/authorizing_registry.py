from __future__ import annotations

import hmac
from pathlib import Path

from dahe.application.template_studio.development_evaluation import (
    AuthorizingDevelopmentDataset,
    FrozenDevelopmentFixtureError,
    load_authorizing_development_dataset,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_APPROVED_RELATIVE_PATH = Path("verification/loops/loop-7/authorizing-development-dataset-v4.json")
_APPROVED_SHA256 = "1f582c8cf161ec577d0298f1de2a9336e63fbb32f325fb13728deabf0c530588"


def approved_authorizing_development_dataset_path() -> Path:
    """Return the one version-controlled dataset approved by this build."""

    return (_PROJECT_ROOT / _APPROVED_RELATIVE_PATH).resolve(strict=True)


def load_approved_authorizing_development_dataset(
    manifest_path: Path,
) -> AuthorizingDevelopmentDataset:
    """Deny persistence unless path and bytes match the code-owned registry."""

    try:
        requested = manifest_path.resolve(strict=True)
        approved = approved_authorizing_development_dataset_path()
    except OSError as exc:
        raise FrozenDevelopmentFixtureError("approved authorizing dataset is unavailable") from exc
    if requested != approved:
        raise FrozenDevelopmentFixtureError(
            "persistent evaluation requires the code-approved authorizing dataset path"
        )
    dataset = load_authorizing_development_dataset(approved)
    if not hmac.compare_digest(dataset.manifest_sha256, _APPROVED_SHA256):
        raise FrozenDevelopmentFixtureError(
            "code-approved authorizing dataset canonical SHA-256 does not match registry"
        )
    return dataset
