from __future__ import annotations

import hashlib
import json
import random
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

from dahe.verification.controlled_non_ticket_challenge import (
    ChallengeContext,
    ControlledNonTicketChallengeError,
    RedactionRectangle,
    create_controlled_non_ticket_challenge,
    load_controlled_non_ticket_challenge,
)
from dahe.verification.image_similarity import (
    ImagePerceptualFingerprint,
    build_image_fingerprint,
)
from tools import loop7_controlled_non_ticket_challenge as cli


def _png_bytes(seed: int, *, size: tuple[int, int] = (96, 72)) -> bytes:
    pixels = random.Random(seed).randbytes(size[0] * size[1])
    image = Image.frombytes("L", size, pixels).convert("RGB")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _source_document_bytes() -> bytes:
    image = Image.new("RGB", (320, 240), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((10, 10, 309, 229), outline=(0, 64, 128), width=5)
    draw.text((72, 24), "UNRELATED AWARD NOTICE", fill="black")
    draw.text((25, 90), "contact: 13800000000", fill="black")
    draw.text((25, 130), "amount: 123456.78", fill="black")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _fingerprints(
    start: int,
    count: int,
) -> tuple[ImagePerceptualFingerprint, ...]:
    return tuple(build_image_fingerprint(_png_bytes(start + index)) for index in range(count))


def _context(
    *,
    development: tuple[ImagePerceptualFingerprint, ...] | None = None,
    locked: tuple[ImagePerceptualFingerprint, ...] | None = None,
) -> ChallengeContext:
    return ChallengeContext(
        development_authority_sha256=hashlib.sha256(b"development authority").hexdigest(),
        development_fingerprints=development or _fingerprints(1000, 3),
        package_sha256=hashlib.sha256(b"locked package").hexdigest(),
        locked_set_fingerprints=locked or _fingerprints(2000, 100),
    )


def _create(
    tmp_path: Path,
    *,
    context: ChallengeContext | None = None,
) -> tuple[Path, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "secret-source.png"
    source.write_bytes(_source_document_bytes())
    artifact = create_controlled_non_ticket_challenge(
        source_image=source,
        output_root=tmp_path / "app-data",
        redactions=(
            RedactionRectangle(20, 82, 235, 112),
            RedactionRectangle(20, 122, 235, 152),
        ),
        operator_id="尹浩远",
        created_at=datetime(2026, 7, 27, 15, 0, tzinfo=UTC),
        context=context or _context(),
    )
    return source, artifact


def test_create_writes_only_content_addressed_redacted_evidence_and_safe_manifest(
    tmp_path: Path,
) -> None:
    source, artifact = _create(tmp_path)
    payload = artifact.payload

    assert artifact.manifest_path.is_file()
    assert artifact.redacted_image_path.is_file()
    assert artifact.redacted_image_path.name == "redacted.png"
    assert artifact.manifest_path.name == "manifest.json"
    assert artifact.manifest_path.parent.name == payload["redacted_sha256"]
    assert artifact.manifest_path.parent.parent.name == str(payload["redacted_sha256"])[:2]

    stored = json.loads(artifact.manifest_path.read_text(encoding="utf-8"))
    assert stored == payload
    assert set(stored) == {
        "canonical_sha256",
        "created_at",
        "development_authority_sha256",
        "dimensions",
        "expected_safety_outcome",
        "human_truth",
        "kind",
        "novelty_results",
        "operator_id",
        "package_sha256",
        "redacted_sha256",
        "redaction_algorithm_version",
        "redactions",
        "schema_version",
        "similarity_algorithm_version",
        "source_sha256",
        "source_fingerprint",
    }
    serialized = artifact.manifest_path.read_text(encoding="utf-8")
    assert str(source) not in serialized
    assert "13800000000" not in serialized
    assert "123456.78" not in serialized
    assert payload["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert payload["redacted_sha256"] == hashlib.sha256(
        artifact.redacted_image_path.read_bytes()
    ).hexdigest()
    assert payload["dimensions"] == {"height": 240, "width": 320}
    assert payload["human_truth"] == {
        "document_class": "non_ticket",
        "ordinary_net": None,
        "ticket_role": "unknown",
    }
    assert payload["expected_safety_outcome"] == {
        "automatic_outcome": "awaiting_review",
        "role_issue": "role_unknown",
        "safety_route": "non_automatic",
    }
    assert payload["source_fingerprint"]["content_sha256"] == payload["source_sha256"]

    with Image.open(artifact.redacted_image_path) as redacted:
        assert redacted.mode == "RGB"
        assert redacted.getpixel((30, 90)) == (0, 0, 0)
        assert redacted.getpixel((30, 130)) == (0, 0, 0)
        assert redacted.info == {}

    assert source.read_bytes() == _source_document_bytes()
    assert sorted(path.name for path in artifact.manifest_path.parent.iterdir()) == [
        "manifest.json",
        "redacted.png",
    ]
    assert all(
        result["passed"] is True
        and result["exact_match_count"] == 0
        and result["near_duplicate_candidate_count"] == 0
        for result in payload["novelty_results"].values()
    )

    source.unlink()
    persistent = load_controlled_non_ticket_challenge(
        manifest_path=artifact.manifest_path,
        context=_context(),
    )
    assert persistent.payload == payload


def test_exact_or_perceptual_reuse_fails_closed_before_any_output(
    tmp_path: Path,
) -> None:
    source_bytes = _source_document_bytes()
    source_fingerprint = build_image_fingerprint(source_bytes)
    jpeg = BytesIO()
    with Image.open(BytesIO(source_bytes)) as image:
        image.save(jpeg, format="JPEG", quality=75)
    near_source = build_image_fingerprint(jpeg.getvalue())
    source = tmp_path / "source.png"
    source.write_bytes(source_bytes)

    for label, development in (
        ("exact", (source_fingerprint,)),
        ("near", (near_source,)),
    ):
        output_root = tmp_path / label
        with pytest.raises(ControlledNonTicketChallengeError, match="development"):
            create_controlled_non_ticket_challenge(
                source_image=source,
                output_root=output_root,
                redactions=(RedactionRectangle(20, 82, 235, 112),),
                operator_id="reviewer",
                created_at="2026-07-27T15:00:00+08:00",
                context=_context(development=development),
            )
        assert not output_root.exists()


def test_redacted_image_must_be_distinct_from_all_current_locked_images(
    tmp_path: Path,
) -> None:
    source, first = _create(tmp_path / "first")
    redacted_fingerprint = build_image_fingerprint(first.redacted_image_path.read_bytes())
    locked = (redacted_fingerprint, *_fingerprints(3000, 99))

    with pytest.raises(ControlledNonTicketChallengeError, match="locked set"):
        create_controlled_non_ticket_challenge(
            source_image=source,
            output_root=tmp_path / "blocked",
            redactions=(
                RedactionRectangle(20, 82, 235, 112),
                RedactionRectangle(20, 122, 235, 152),
            ),
            operator_id="reviewer",
            created_at="2026-07-27T15:00:00+08:00",
            context=_context(locked=locked),
        )
    assert not (tmp_path / "blocked").exists()


def test_create_is_byte_idempotent_and_loader_recomputes_every_binding(
    tmp_path: Path,
) -> None:
    context = _context()
    source, first = _create(tmp_path, context=context)
    first_manifest = first.manifest_path.read_bytes()
    first_image = first.redacted_image_path.read_bytes()

    second = create_controlled_non_ticket_challenge(
        source_image=source,
        output_root=tmp_path / "app-data",
        redactions=(
            RedactionRectangle(20, 82, 235, 112),
            RedactionRectangle(20, 122, 235, 152),
        ),
        operator_id="尹浩远",
        created_at="2026-07-27T15:00:00+00:00",
        context=context,
    )
    loaded = load_controlled_non_ticket_challenge(
        manifest_path=first.manifest_path,
        source_image=source,
        context=context,
    )

    assert second.payload == first.payload == loaded.payload
    assert first.manifest_path.read_bytes() == first_manifest
    assert first.redacted_image_path.read_bytes() == first_image

    changed_context = ChallengeContext(
        development_authority_sha256=hashlib.sha256(b"changed authority").hexdigest(),
        development_fingerprints=context.development_fingerprints,
        package_sha256=context.package_sha256,
        locked_set_fingerprints=context.locked_set_fingerprints,
    )
    with pytest.raises(ControlledNonTicketChallengeError, match="authority"):
        load_controlled_non_ticket_challenge(
            manifest_path=first.manifest_path,
            source_image=source,
            context=changed_context,
        )


def test_tampering_invalid_rectangles_and_changed_source_fail_closed(
    tmp_path: Path,
) -> None:
    context = _context()
    source, artifact = _create(tmp_path, context=context)

    with pytest.raises(ControlledNonTicketChallengeError, match="rectangle"):
        create_controlled_non_ticket_challenge(
            source_image=source,
            output_root=tmp_path / "invalid",
            redactions=(RedactionRectangle(10, 10, 400, 20),),
            operator_id="reviewer",
            created_at="2026-07-27T15:00:00+08:00",
            context=context,
        )

    source.write_bytes(_png_bytes(999, size=(320, 240)))
    with pytest.raises(ControlledNonTicketChallengeError, match="source"):
        load_controlled_non_ticket_challenge(
            manifest_path=artifact.manifest_path,
            source_image=source,
            context=context,
        )

    source.write_bytes(_source_document_bytes())
    artifact.redacted_image_path.write_bytes(_png_bytes(998, size=(320, 240)))
    with pytest.raises(ControlledNonTicketChallengeError, match="redacted"):
        load_controlled_non_ticket_challenge(
            manifest_path=artifact.manifest_path,
            source_image=source,
            context=context,
        )


def test_cli_accepts_repeated_rectangles_without_disclosing_source_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "private-source-name.png"
    source.write_bytes(_source_document_bytes())
    context = _context()
    monkeypatch.setattr(
        cli,
        "load_controlled_challenge_context",
        lambda **_: context,
    )

    assert (
        cli.main(
            [
                "create",
                "--source-image",
                str(source),
                "--output-root",
                str(tmp_path / "app-data"),
                "--development-authority",
                str(tmp_path / "authority.json"),
                "--package-data-root",
                str(tmp_path / "package"),
                "--operator",
                "尹浩远",
                "--created-at",
                "2026-07-27T23:00:00+08:00",
                "--redact",
                "20,82,235,112",
                "--redact",
                "20,122,235,152",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)

    assert result["verified"] is True
    assert result["action"] == "create"
    assert result["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert str(source) not in json.dumps(result, ensure_ascii=False)


def test_source_symlink_is_rejected(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.png"
    source.write_bytes(_source_document_bytes())
    link = tmp_path / "source-link.png"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symbolic links are not available in this Windows environment")

    with pytest.raises(ControlledNonTicketChallengeError, match="symbolic link"):
        create_controlled_non_ticket_challenge(
            source_image=link,
            output_root=tmp_path / "app-data",
            redactions=(RedactionRectangle(20, 82, 235, 112),),
            operator_id="reviewer",
            created_at="2026-07-27T15:00:00+08:00",
            context=_context(),
        )
