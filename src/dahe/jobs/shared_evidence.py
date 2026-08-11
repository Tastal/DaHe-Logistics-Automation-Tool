from __future__ import annotations

import hashlib
import json


def shared_evidence_fingerprint(
    image_sha256: str,
    pipeline_fingerprint: str,
) -> str:
    """Build a stable identity without making the image path part of the key."""
    payload = json.dumps(
        {
            "image_sha256": image_sha256,
            "pipeline_fingerprint": pipeline_fingerprint,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()
