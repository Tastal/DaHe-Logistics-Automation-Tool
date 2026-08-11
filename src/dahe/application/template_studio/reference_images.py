from __future__ import annotations

import hashlib
import io
import json
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal

from PIL import Image, ImageDraw, ImageOps, UnidentifiedImageError

from dahe.domain.ticket.templates import NormalizedRect

MAX_REFERENCE_BYTES = 15 * 1024 * 1024
MAX_REFERENCE_PIXELS = 30_000_000
MAX_REFERENCE_EDGE = 12_000
MIN_REFERENCE_EDGE = 16
SUPPORTED_MEDIA_TYPES = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
}


class TemplateReferenceImageError(ValueError):
    """Raised when local reference bytes are unsafe or not a supported image."""


@dataclass(frozen=True, slots=True)
class NormalizedTemplateReference:
    content: bytes
    media_type: str
    width: int
    height: int
    source_format: str
    orientation_normalized: bool


def build_template_reference_mask(
    *,
    width: int,
    height: int,
    anchors: Sequence[NormalizedRect],
) -> bytes:
    """Render a deterministic local PNG mask for stable reference anchors."""

    _check_dimensions(width, height)
    if not anchors or any(not isinstance(anchor, NormalizedRect) for anchor in anchors):
        raise TemplateReferenceImageError(
            "reference mask requires at least one valid anchor"
        )
    mask = Image.new("1", (width, height), color=0)
    draw = ImageDraw.Draw(mask)
    for anchor in anchors:
        left = int(
            (anchor.x * Decimal(width)).to_integral_value(
                rounding=ROUND_FLOOR
            )
        )
        top = int(
            (anchor.y * Decimal(height)).to_integral_value(
                rounding=ROUND_FLOOR
            )
        )
        right = int(
            (
                (anchor.x + anchor.width) * Decimal(width)
            ).to_integral_value(rounding=ROUND_CEILING)
        ) - 1
        bottom = int(
            (
                (anchor.y + anchor.height) * Decimal(height)
            ).to_integral_value(rounding=ROUND_CEILING)
        ) - 1
        draw.rectangle(
            (
                max(0, left),
                max(0, top),
                min(width - 1, right),
                min(height - 1, bottom),
            ),
            fill=1,
        )
    output = io.BytesIO()
    mask.save(output, format="PNG", compress_level=6, optimize=False)
    return output.getvalue()


def template_reference_alignment_fingerprint(
    *,
    image_sha256: str,
    width: int,
    height: int,
) -> str:
    """Identify the server-normalized, top-left image coordinate system."""

    payload = {
        "coordinate_space": "normalized_top_left_v1",
        "height": height,
        "image_sha256": image_sha256,
        "orientation": "exif_transposed",
        "width": width,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _check_dimensions(width: int, height: int) -> None:
    if width < MIN_REFERENCE_EDGE or height < MIN_REFERENCE_EDGE:
        raise TemplateReferenceImageError("reference image is too small")
    if width > MAX_REFERENCE_EDGE or height > MAX_REFERENCE_EDGE:
        raise TemplateReferenceImageError("reference image edge is too large")
    if width * height > MAX_REFERENCE_PIXELS:
        raise TemplateReferenceImageError("reference image has too many pixels")


def normalize_template_reference_image(
    content: bytes,
    *,
    declared_media_type: str,
) -> NormalizedTemplateReference:
    """Decode and rewrite one local PNG/JPEG without retaining metadata."""

    if not isinstance(content, bytes) or not content:
        raise TemplateReferenceImageError("reference image bytes are required")
    if len(content) > MAX_REFERENCE_BYTES:
        raise TemplateReferenceImageError("reference image exceeds the byte limit")
    expected_format = SUPPORTED_MEDIA_TYPES.get(declared_media_type)
    if expected_format is None:
        raise TemplateReferenceImageError("reference image type is unsupported")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(content)) as probe:
                source_format = probe.format
                if source_format != expected_format:
                    raise TemplateReferenceImageError(
                        "reference image type does not match its bytes"
                    )
                if getattr(probe, "n_frames", 1) != 1:
                    raise TemplateReferenceImageError(
                        "animated reference images are unsupported"
                    )
                _check_dimensions(*probe.size)
                probe.verify()

            with Image.open(io.BytesIO(content)) as decoded:
                decoded.load()
                normalized = ImageOps.exif_transpose(decoded)
                _check_dimensions(*normalized.size)
                orientation_normalized = normalized.size != decoded.size
                target_mode = "RGBA" if "A" in normalized.getbands() else "RGB"
                rewritten = normalized.convert(target_mode)
                output = io.BytesIO()
                rewritten.save(
                    output,
                    format="PNG",
                    compress_level=6,
                    optimize=False,
                )
    except TemplateReferenceImageError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
    ) as exc:
        raise TemplateReferenceImageError(
            "reference image could not be decoded safely"
        ) from exc

    return NormalizedTemplateReference(
        content=output.getvalue(),
        media_type="image/png",
        width=rewritten.width,
        height=rewritten.height,
        source_format=source_format,
        orientation_normalized=orientation_normalized,
    )
