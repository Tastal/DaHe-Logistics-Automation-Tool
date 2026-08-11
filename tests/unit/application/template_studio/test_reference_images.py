from __future__ import annotations

import hashlib
import io
from decimal import Decimal

import pytest
from PIL import Image

from dahe.application.template_studio import reference_images
from dahe.application.template_studio.reference_images import (
    TemplateReferenceImageError,
    build_template_reference_mask,
    normalize_template_reference_image,
    template_reference_alignment_fingerprint,
)
from dahe.domain.ticket.templates import NormalizedRect


def _image_bytes(
    image_format: str,
    *,
    size: tuple[int, int] = (64, 40),
    exif_orientation: int | None = None,
) -> bytes:
    image = Image.new("RGB", size, color=(240, 240, 240))
    exif = Image.Exif()
    if exif_orientation is not None:
        exif[274] = exif_orientation
    output = io.BytesIO()
    image.save(output, format=image_format, exif=exif)
    return output.getvalue()


def test_png_and_oriented_jpeg_are_decoded_and_rewritten_without_metadata() -> None:
    png = normalize_template_reference_image(
        _image_bytes("PNG"),
        declared_media_type="image/png",
    )
    jpeg = normalize_template_reference_image(
        _image_bytes("JPEG", size=(64, 40), exif_orientation=6),
        declared_media_type="image/jpeg",
    )

    assert png.media_type == "image/png"
    assert (png.width, png.height) == (64, 40)
    assert png.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert (jpeg.width, jpeg.height) == (40, 64)
    assert jpeg.orientation_normalized is True
    with Image.open(io.BytesIO(jpeg.content)) as decoded:
        assert decoded.getexif().get(274) is None


@pytest.mark.parametrize(
    ("content", "media_type"),
    [
        (b"<svg xmlns='http://www.w3.org/2000/svg'/>", "image/png"),
        (_image_bytes("PNG"), "image/jpeg"),
        (_image_bytes("GIF"), "image/png"),
        (b"not an image", "image/png"),
    ],
)
def test_reference_validation_rejects_spoofed_or_unsupported_content(
    content: bytes,
    media_type: str,
) -> None:
    with pytest.raises(TemplateReferenceImageError):
        normalize_template_reference_image(
            content,
            declared_media_type=media_type,
        )


def test_reference_validation_rejects_byte_and_pixel_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reference_images, "MAX_REFERENCE_BYTES", 10)
    with pytest.raises(TemplateReferenceImageError, match="byte limit"):
        normalize_template_reference_image(
            _image_bytes("PNG"),
            declared_media_type="image/png",
        )

    monkeypatch.setattr(reference_images, "MAX_REFERENCE_BYTES", 1024 * 1024)
    monkeypatch.setattr(reference_images, "MAX_REFERENCE_PIXELS", 100)
    with pytest.raises(TemplateReferenceImageError, match="too many pixels"):
        normalize_template_reference_image(
            _image_bytes("PNG"),
            declared_media_type="image/png",
        )


def test_reference_mask_and_alignment_are_deterministic_server_artifacts() -> None:
    anchor = NormalizedRect(
        x=Decimal("0.10"),
        y=Decimal("0.20"),
        width=Decimal("0.30"),
        height=Decimal("0.10"),
    )
    first = build_template_reference_mask(
        width=100,
        height=50,
        anchors=(anchor,),
    )
    second = build_template_reference_mask(
        width=100,
        height=50,
        anchors=(anchor,),
    )

    assert first == second
    with Image.open(io.BytesIO(first)) as mask:
        assert mask.size == (100, 50)
        assert mask.getpixel((15, 12)) != 0
        assert mask.getpixel((80, 40)) == 0
    assert template_reference_alignment_fingerprint(
        image_sha256=hashlib.sha256(b"reference").hexdigest(),
        width=100,
        height=50,
    ) == template_reference_alignment_fingerprint(
        image_sha256=hashlib.sha256(b"reference").hexdigest(),
        width=100,
        height=50,
    )
