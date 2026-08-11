from __future__ import annotations

import importlib
import io
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


@contextmanager
def _worker_engine(project_root: Path) -> Iterator[ModuleType]:
    worker_src = str(project_root / "ocr-runtime" / "src")
    sys.path.insert(0, worker_src)
    try:
        yield importlib.import_module("dahe_ocr_worker.engine")
    finally:
        sys.path.remove(worker_src)
        for module_name in tuple(sys.modules):
            if module_name == "dahe_ocr_worker" or module_name.startswith("dahe_ocr_worker."):
                sys.modules.pop(module_name, None)


@pytest.mark.parametrize(
    "payload",
    [
        {"rec_texts": ["NET 12.34"], "rec_scores": [], "rec_boxes": [[0, 0, 1, 1]]},
        {
            "rec_texts": ["NET 12.34"],
            "rec_scores": [0.9],
            "rec_boxes": [[0, 0, 1, 1], [1, 1, 2, 2]],
        },
        {"rec_texts": "NET 12.34", "rec_scores": [0.9], "rec_boxes": [[0, 0, 1, 1]]},
    ],
)
def test_paddle_output_arrays_must_be_sequences_with_equal_lengths(
    project_root: Path,
    payload: dict[str, object],
) -> None:
    with _worker_engine(project_root) as engine, pytest.raises(RuntimeError, match="aligned"):
        engine._validated_prediction_arrays(payload)


def test_paddle_output_arrays_accept_one_aligned_prediction(project_root: Path) -> None:
    payload = {
        "rec_texts": ["NET 12.34"],
        "rec_scores": [0.9],
        "rec_boxes": [[0, 0, 1, 1]],
    }
    with _worker_engine(project_root) as engine:
        texts, scores, boxes = engine._validated_prediction_arrays(payload)

    assert texts == ["NET 12.34"]
    assert scores == [0.9]
    assert boxes == [[0, 0, 1, 1]]


def test_worker_normalized_box_stays_inside_decimal_protocol_boundary(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        box = engine._normalized_box(
            left=953,
            top=607,
            right=1000,
            bottom=657,
            image_width=1000,
            image_height=1500,
        )

    assert Decimal(str(box["x"])) + Decimal(str(box["width"])) <= 1
    assert Decimal(str(box["y"])) + Decimal(str(box["height"])) <= 1


@pytest.mark.parametrize(
    ("coordinates", "message"),
    [
        ({"left": 30, "top": 10, "right": 20, "bottom": 40}, "non-positive"),
        ({"left": 10, "top": 40, "right": 30, "bottom": 20}, "non-positive"),
        ({"left": 10, "top": 10, "right": 10, "bottom": 40}, "non-positive"),
        ({"left": -30, "top": 10, "right": -10, "bottom": 40}, "outside"),
        ({"left": 110, "top": 10, "right": 130, "bottom": 40}, "outside"),
        ({"left": 10, "top": -30, "right": 30, "bottom": -10}, "outside"),
        ({"left": 10, "top": 110, "right": 30, "bottom": 130}, "outside"),
    ],
)
def test_worker_rejects_non_positive_or_wholly_outside_text_boxes(
    project_root: Path,
    coordinates: dict[str, int],
    message: str,
) -> None:
    with _worker_engine(project_root) as engine, pytest.raises(RuntimeError, match=message):
        engine._normalized_box(
            **coordinates,
            image_width=100,
            image_height=100,
        )


def test_worker_clips_a_valid_positive_text_box_intersection(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        box = engine._normalized_box(
            left=-10,
            top=10,
            right=20,
            bottom=120,
            image_width=100,
            image_height=100,
        )

    assert box == {
        "x": 0.0,
        "y": 0.1,
        "width": 0.2,
        "height": 0.9,
    }


@pytest.mark.parametrize("coordinate", [float("nan"), float("inf"), float("-inf")])
def test_worker_rejects_non_finite_text_box_coordinates(
    project_root: Path,
    coordinate: float,
) -> None:
    with (
        _worker_engine(project_root) as engine,
        pytest.raises(
            RuntimeError,
            match="non-finite text box",
        ),
    ):
        engine._normalized_box(
            left=coordinate,
            top=10,
            right=20,
            bottom=20,
            image_width=100,
            image_height=100,
        )


@pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf")])
def test_worker_rejects_non_finite_recognition_scores(
    project_root: Path,
    score: float,
) -> None:
    prediction = SimpleNamespace(
        json={
            "res": {
                "rec_texts": ["NET"],
                "rec_scores": [score],
                "rec_boxes": [[10, 10, 20, 20]],
            }
        }
    )
    pipeline = SimpleNamespace(
        predict=lambda _image, **_options: [prediction],
    )

    with _worker_engine(project_root) as engine:
        worker = object.__new__(engine.PaddleEngine)
        with pytest.raises(RuntimeError, match="non-finite recognition score"):
            worker._predict_lines(
                pipeline=pipeline,
                image_array=object(),
                width=100,
                height=100,
            )


@pytest.mark.parametrize("score", [-0.01, 1.01])
def test_worker_rejects_finite_recognition_scores_outside_probability_range(
    project_root: Path,
    score: float,
) -> None:
    prediction = SimpleNamespace(
        json={
            "res": {
                "rec_texts": ["NET"],
                "rec_scores": [score],
                "rec_boxes": [[10, 10, 20, 20]],
            }
        }
    )
    pipeline = SimpleNamespace(
        predict=lambda _image, **_options: [prediction],
    )

    with _worker_engine(project_root) as engine:
        worker = object.__new__(engine.PaddleEngine)
        with pytest.raises(RuntimeError, match="outside"):
            worker._predict_lines(
                pipeline=pipeline,
                image_array=object(),
                width=100,
                height=100,
            )


def _ocr_line(
    text: str,
    *,
    x: float,
    y: float,
    width: float,
    height: float,
    confidence: float = 0.99,
) -> dict[str, object]:
    return {
        "text": text,
        "confidence": confidence,
        "box": {
            "x": x,
            "y": y,
            "width": width,
            "height": height,
        },
    }


def test_worker_extracts_weight_from_the_nearest_right_hand_value(
    project_root: Path,
) -> None:
    lines = [
        _ocr_line("皮重", x=0.61, y=0.38, width=0.06, height=0.04),
        _ocr_line("12.34", x=0.69, y=0.39, width=0.08, height=0.04),
        _ocr_line("毛重", x=0.61, y=0.48, width=0.06, height=0.04),
        _ocr_line("45.67", x=0.69, y=0.48, width=0.08, height=0.04),
        _ocr_line("净重", x=0.61, y=0.58, width=0.06, height=0.04),
        _ocr_line(
            "33.33",
            x=0.69,
            y=0.58,
            width=0.08,
            height=0.04,
            confidence=0.97,
        ),
    ]

    with _worker_engine(project_root) as engine:
        fields = engine.PaddleEngine._parse_fields(lines)

    assert fields["ordinary_net"] == {
        "raw_text": "33.33",
        "amount": "33.33",
        "unit": "t",
        "confidence": 0.97,
    }
    assert fields["gross"]["amount"] == "45.67"
    assert fields["tare"]["amount"] == "12.34"


def test_worker_keeps_factory_net_separate_from_ordinary_net(
    project_root: Path,
) -> None:
    lines = [
        _ocr_line("净重", x=0.58, y=0.46, width=0.04, height=0.02),
        _ocr_line("31.25", x=0.72, y=0.46, width=0.04, height=0.02),
        _ocr_line("工厂净重", x=0.56, y=0.49, width=0.07, height=0.02),
        _ocr_line("31.30", x=0.72, y=0.49, width=0.04, height=0.02),
    ]

    with _worker_engine(project_root) as engine:
        fields = engine.PaddleEngine._parse_fields(lines)

    assert fields["ordinary_net"]["amount"] == "31.25"
    assert fields["factory_net"]["amount"] == "31.30"


def test_worker_does_not_pair_a_weight_label_with_an_unrelated_number(
    project_root: Path,
) -> None:
    lines = [
        _ocr_line("净重", x=0.58, y=0.46, width=0.04, height=0.02),
        _ocr_line(
            "2026-07-26 12:34:56",
            x=0.68,
            y=0.55,
            width=0.22,
            height=0.02,
        ),
        _ocr_line("31.25", x=0.10, y=0.46, width=0.04, height=0.02),
    ]

    with _worker_engine(project_root) as engine:
        fields = engine.PaddleEngine._parse_fields(lines)

    assert "ordinary_net" not in fields


def test_worker_marks_explicit_kilogram_weight_for_downstream_review(
    project_root: Path,
) -> None:
    lines = [
        _ocr_line("净重", x=0.58, y=0.46, width=0.04, height=0.02),
        _ocr_line("31250 kg", x=0.72, y=0.46, width=0.08, height=0.02),
    ]

    with _worker_engine(project_root) as engine:
        fields = engine.PaddleEngine._parse_fields(lines)

    assert fields["ordinary_net"]["amount"] == "31250"
    assert fields["ordinary_net"]["unit"] == "kg"


@pytest.mark.parametrize(
    "text",
    [
        "FACTORYNETWORK 31.25",
        "GROSSER 44.10",
        "TAREFUL 12.00",
        "NETWORK 31.25",
    ],
)
def test_worker_does_not_create_fields_from_labels_inside_larger_english_words(
    project_root: Path,
    text: str,
) -> None:
    lines = [
        _ocr_line(
            text,
            x=0.1,
            y=0.1,
            width=0.4,
            height=0.05,
        )
    ]

    with _worker_engine(project_root) as engine:
        fields = engine.PaddleEngine._parse_fields(lines)

    assert fields == {}


@pytest.mark.parametrize(
    ("text", "field"),
    [
        ("FACTORY-NET 31.25", "factory_net"),
        ("GROSS: 44.10", "gross"),
        ("TARE 12.00", "tare"),
        ("净重 31.25", "ordinary_net"),
    ],
)
def test_worker_preserves_valid_chinese_and_boundary_safe_english_field_labels(
    project_root: Path,
    text: str,
    field: str,
) -> None:
    lines = [
        _ocr_line(
            text,
            x=0.1,
            y=0.1,
            width=0.4,
            height=0.05,
        )
    ]

    with _worker_engine(project_root) as engine:
        fields = engine.PaddleEngine._parse_fields(lines)

    assert fields[field]["amount"] in text


def _install_fake_image_decoder(
    monkeypatch: pytest.MonkeyPatch,
    *,
    size: tuple[int, int],
    captured: list[bytes],
) -> None:
    class FakeImage:
        def __init__(self) -> None:
            self.size = size

        def __enter__(self) -> FakeImage:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def load(self) -> None:
            return None

        def convert(self, mode: str) -> FakeImage:
            assert mode == "RGB"
            return self

    class FakeImageModule:
        class DecompressionBombWarning(Warning):
            pass

        @staticmethod
        def open(stream: object) -> FakeImage:
            captured.append(stream.read())  # type: ignore[attr-defined]
            return FakeImage()

    class FakeImageOpsModule:
        @staticmethod
        def exif_transpose(source: FakeImage) -> FakeImage:
            return source

    numpy = ModuleType("numpy")
    numpy.asarray = lambda _value: SimpleNamespace(shape=(size[1], size[0], 3))  # type: ignore[attr-defined]
    numpy.ascontiguousarray = lambda value: value  # type: ignore[attr-defined]
    pil = ModuleType("PIL")
    pil.Image = FakeImageModule  # type: ignore[attr-defined]
    pil.ImageOps = FakeImageOpsModule  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "numpy", numpy)
    monkeypatch.setitem(sys.modules, "PIL", pil)


def test_worker_decodes_the_captured_bytes_without_a_source_path(
    project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[bytes] = []
    _install_fake_image_decoder(
        monkeypatch,
        size=(3, 2),
        captured=captured,
    )
    with _worker_engine(project_root) as engine:
        image_array, width, height = engine.PaddleEngine._decode_image(b"captured-image-bytes")

    assert (width, height) == (3, 2)
    assert tuple(image_array.shape) == (2, 3, 3)
    assert captured == [b"captured-image-bytes"]


def test_worker_rejects_captured_image_above_the_pixel_limit(
    project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_image_decoder(
        monkeypatch,
        size=(2, 2),
        captured=[],
    )
    with _worker_engine(project_root) as engine:
        monkeypatch.setattr(engine, "MAX_IMAGE_PIXELS", 3)
        with pytest.raises(
            engine.WorkerProtocolViolation,
            match="pixel limit",
        ):
            engine.PaddleEngine._decode_image(b"oversized-pixel-image")


def test_worker_applies_exif_orientation_before_array_conversion(
    project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from PIL import Image

    encoded = io.BytesIO()
    source = Image.new("RGB", (3, 2), color=(12, 34, 56))
    exif = Image.Exif()
    exif[274] = 6
    source.save(encoded, format="JPEG", exif=exif)

    numpy = ModuleType("numpy")
    numpy.asarray = lambda value: SimpleNamespace(  # type: ignore[attr-defined]
        shape=(value.height, value.width, 3)
    )
    numpy.ascontiguousarray = lambda value: value  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "numpy", numpy)

    with _worker_engine(project_root) as engine:
        image_array, width, height = engine.PaddleEngine._decode_image(encoded.getvalue())

    assert (width, height) == (2, 3)
    assert tuple(image_array.shape) == (3, 2, 3)


def test_worker_recovers_a_jpeg_missing_only_its_end_marker(
    project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from PIL import Image

    encoded = io.BytesIO()
    Image.new("RGB", (12, 8), color=(12, 34, 56)).save(
        encoded,
        format="JPEG",
    )
    captured = encoded.getvalue()
    assert captured.endswith(b"\xff\xd9")

    numpy = ModuleType("numpy")
    numpy.asarray = lambda value: SimpleNamespace(  # type: ignore[attr-defined]
        shape=(value.height, value.width, 3)
    )
    numpy.ascontiguousarray = lambda value: value  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "numpy", numpy)

    with _worker_engine(project_root) as engine:
        image_array, width, height = engine.PaddleEngine._decode_image(
            captured[:-2]
        )

    assert (width, height) == (12, 8)
    assert tuple(image_array.shape) == (8, 12, 3)


def test_worker_does_not_repair_a_truncated_non_jpeg(
    project_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from PIL import Image

    encoded = io.BytesIO()
    Image.new("RGB", (12, 8), color=(12, 34, 56)).save(
        encoded,
        format="PNG",
    )

    numpy = ModuleType("numpy")
    numpy.asarray = lambda value: SimpleNamespace(  # type: ignore[attr-defined]
        shape=(value.height, value.width, 3)
    )
    numpy.ascontiguousarray = lambda value: value  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "numpy", numpy)

    with _worker_engine(project_root) as engine, pytest.raises(OSError):
        engine.PaddleEngine._decode_image(encoded.getvalue()[:-20])


@pytest.mark.parametrize(
    ("source_orientation", "expected_box"),
    [
        (
            90,
            {
                "x": 0.8,
                "y": 0.1,
                "width": 0.1,
                "height": 0.2,
            },
        ),
        (
            180,
            {
                "x": 0.7,
                "y": 0.8,
                "width": 0.2,
                "height": 0.1,
            },
        ),
        (
            270,
            {
                "x": 0.1,
                "y": 0.7,
                "width": 0.1,
                "height": 0.2,
            },
        ),
    ],
)
def test_worker_recovers_raw_quarter_turns_without_losing_source_geometry(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_orientation: int,
    expected_box: dict[str, float],
) -> None:
    class FakeImageArray:
        def __init__(self, correction_degrees: int) -> None:
            self.correction_degrees = correction_degrees

    numpy = ModuleType("numpy")
    numpy.rot90 = lambda value, k: FakeImageArray(  # type: ignore[attr-defined]
        (value.correction_degrees + (90 * k)) % 360
    )
    numpy.ascontiguousarray = lambda value: value  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "numpy", numpy)

    prediction_calls: list[int] = []

    class FakePrediction:
        def __init__(self, payload: dict[str, object]) -> None:
            self.json = {"res": payload}

    class FakePipeline:
        def predict(
            self,
            image_array: FakeImageArray,
            **_options: object,
        ) -> list[FakePrediction]:
            prediction_calls.append(image_array.correction_degrees)
            if image_array.correction_degrees != source_orientation:
                if source_orientation == 90 and image_array.correction_degrees == 0:
                    return [
                        FakePrediction(
                            {
                                "rec_texts": [
                                    "UNLOADING TICKET",
                                    "FACTORYNET",
                                    "GROSS",
                                ],
                                "rec_scores": [0.99, 0.98, 0.97],
                                "rec_boxes": [
                                    [10, 10, 20, 50],
                                    [30, 10, 40, 50],
                                    [50, 10, 60, 50],
                                ],
                            }
                        )
                    ]
                return [
                    FakePrediction(
                        {
                            "rec_texts": ["noise"],
                            "rec_scores": [0.20],
                            "rec_boxes": [[10, 20, 30, 40]],
                        }
                    )
                ]
            corrected_width = 200 if source_orientation in {90, 270} else 100
            corrected_height = 100 if source_orientation in {90, 270} else 200
            return [
                FakePrediction(
                    {
                        "rec_texts": [
                            "UNLOADING TICKET",
                            "FACTORYNET",
                            "31.25",
                            "GROSS",
                        ],
                        "rec_scores": [0.99, 0.98, 0.97, 0.96],
                        "rec_boxes": [
                            [
                                corrected_width * 0.1,
                                corrected_height * 0.1,
                                corrected_width * 0.3,
                                corrected_height * 0.2,
                            ],
                            [
                                corrected_width * 0.1,
                                corrected_height * 0.5,
                                corrected_width * 0.3,
                                corrected_height * 0.6,
                            ],
                            [
                                corrected_width * 0.35,
                                corrected_height * 0.5,
                                corrected_width * 0.5,
                                corrected_height * 0.6,
                            ],
                            [
                                corrected_width * 0.1,
                                corrected_height * 0.7,
                                corrected_width * 0.3,
                                corrected_height * 0.8,
                            ],
                        ],
                    }
                )
            ]

    with _worker_engine(project_root) as engine:
        monkeypatch.setattr(
            engine.PaddleEngine,
            "_decode_image",
            staticmethod(lambda _image_bytes: (FakeImageArray(0), 100, 200)),
        )
        worker = engine.PaddleEngine(
            engine.EngineConfig(
                runtime_kind="cpu",
                current_device_index=None,
                models_dir=tmp_path,
                precision="fp32",
                batch_size=1,
                cpu_threads=1,
            )
        )
        worker._pipeline = FakePipeline()

        result = worker.extract(b"raw-rotated-image")

    assert prediction_calls == [0, 90, 180, 270]
    assert result["role_observation"]["orientation_degrees"] == source_orientation
    assert result["text_lines"][0]["box"] == expected_box
    assert result["fields"]["factory_net"]["amount"] == "31.25"


def test_worker_keeps_the_single_pass_fast_path_for_strong_upright_text(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeImageArray:
        correction_degrees = 0

    prediction_calls = 0

    class FakePrediction:
        def __init__(self) -> None:
            self.json = {
                "res": {
                    "rec_texts": [
                        "LOADING TICKET",
                        "NET",
                        "31.25",
                        "GROSS",
                    ],
                    "rec_scores": [0.99, 0.98, 0.97, 0.96],
                    "rec_boxes": [
                        [10, 10, 40, 20],
                        [10, 50, 20, 60],
                        [25, 50, 40, 60],
                        [10, 70, 20, 80],
                    ],
                }
            }

    class FakePipeline:
        def predict(
            self,
            _image_array: FakeImageArray,
            **_options: object,
        ) -> list[FakePrediction]:
            nonlocal prediction_calls
            prediction_calls += 1
            return [FakePrediction()]

    with _worker_engine(project_root) as engine:
        monkeypatch.setattr(
            engine.PaddleEngine,
            "_decode_image",
            staticmethod(lambda _image_bytes: (FakeImageArray(), 100, 100)),
        )
        worker = engine.PaddleEngine(
            engine.EngineConfig(
                runtime_kind="cpu",
                current_device_index=None,
                models_dir=tmp_path,
                precision="fp32",
                batch_size=1,
                cpu_threads=1,
            )
        )
        worker._pipeline = FakePipeline()

        result = worker.extract(b"upright-image")

    assert prediction_calls == 1
    assert result["role_observation"]["orientation_degrees"] == 0


def test_worker_prefers_usable_field_geometry_when_orientation_markers_tie(
    project_root: Path,
) -> None:
    common = {
        "canonical_lines": [],
        "source_lines": [],
        "role_marker_hits": 2,
        "marker_hits": 6,
        "text_characters": 220,
        "horizontal_text_ratio": 1.0,
    }
    with _worker_engine(project_root) as engine:
        sideways = engine._OcrCandidate(
            orientation_degrees=90,
            canonical_fields={},
            confidence_total=36.0,
            **common,
        )
        upright = engine._OcrCandidate(
            orientation_degrees=180,
            canonical_fields={
                "factory_net": {
                    "raw_text": "33.12",
                    "amount": "33.12",
                    "unit": "t",
                    "confidence": 0.99,
                }
            },
            confidence_total=35.9,
            **common,
        )

    assert upright.rank > sideways.rank


def test_worker_keeps_source_orientation_when_no_role_marker_supports_rotation(
    project_root: Path,
) -> None:
    common = {
        "canonical_lines": [],
        "source_lines": [],
        "role_marker_hits": 0,
        "marker_hits": 3,
        "text_characters": 120,
        "horizontal_text_ratio": 1.0,
    }
    with _worker_engine(project_root) as engine:
        source = engine._OcrCandidate(
            orientation_degrees=0,
            canonical_fields={},
            confidence_total=10.0,
            **common,
        )
        arbitrary_rotation = engine._OcrCandidate(
            orientation_degrees=270,
            canonical_fields={
                "gross": {
                    "raw_text": "48.8",
                    "amount": "48.8",
                    "unit": "t",
                    "confidence": 0.99,
                },
                "tare": {
                    "raw_text": "16.12",
                    "amount": "16.12",
                    "unit": "t",
                    "confidence": 0.99,
                },
            },
            confidence_total=20.0,
            **common,
        )

        selected = engine._select_ocr_candidate((source, arbitrary_rotation))

    assert selected is source


def _orientation_candidate(
    engine: ModuleType,
    *,
    orientation_degrees: int,
    lines: list[dict[str, object]],
    fields: dict[str, dict[str, object]] | None = None,
) -> object:
    evidence = engine._orientation_marker_evidence(lines)
    return engine._OcrCandidate(
        orientation_degrees=orientation_degrees,
        canonical_lines=lines,
        source_lines=lines,
        canonical_fields=fields or {},
        role_marker_hits=evidence.role_marker_hits,
        marker_hits=evidence.marker_hits,
        confidence_total=sum(float(line["confidence"]) for line in lines),
        text_characters=sum(len(str(line["text"])) for line in lines),
        horizontal_text_ratio=1.0,
        supporting_marker_line_hits=evidence.supporting_marker_line_hits,
        independent_marker_line_hits=evidence.independent_marker_line_hits,
    )


def test_worker_ignores_a_low_confidence_false_role_term_during_rotation(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        source = _orientation_candidate(
            engine,
            orientation_degrees=0,
            lines=[
                _ocr_line("Dispatch details", x=0.1, y=0.1, width=0.4, height=0.05),
                _ocr_line("Vehicle", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("Amount", x=0.1, y=0.3, width=0.2, height=0.05),
            ],
        )
        false_rotation = _orientation_candidate(
            engine,
            orientation_degrees=270,
            lines=[
                _ocr_line(
                    "UNLOADING",
                    x=0.1,
                    y=0.1,
                    width=0.3,
                    height=0.05,
                    confidence=0.01,
                ),
                _ocr_line("Invoice", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("Amount", x=0.1, y=0.3, width=0.2, height=0.05),
            ],
            fields={
                "ordinary_net": {
                    "amount": "31.25",
                    "unit": "t",
                    "confidence": 0.99,
                }
            },
        )

        selected = engine._select_ocr_candidate((source, false_rotation))

    assert false_rotation.role_marker_hits == 0
    assert selected is source


def test_worker_retains_source_orientation_for_one_uncorroborated_role_marker(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        source = _orientation_candidate(
            engine,
            orientation_degrees=0,
            lines=[
                _ocr_line("Dispatch details", x=0.1, y=0.1, width=0.4, height=0.05),
                _ocr_line("Vehicle", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("Amount", x=0.1, y=0.3, width=0.2, height=0.05),
            ],
        )
        weak_rotation = _orientation_candidate(
            engine,
            orientation_degrees=270,
            lines=[
                _ocr_line("UNLOADING", x=0.1, y=0.1, width=0.3, height=0.05),
                _ocr_line("Invoice", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("31.25", x=0.4, y=0.2, width=0.2, height=0.05),
            ],
            fields={
                "ordinary_net": {
                    "amount": "31.25",
                    "unit": "t",
                    "confidence": 0.99,
                }
            },
        )

        selected = engine._select_ocr_candidate((source, weak_rotation))

    assert weak_rotation.role_marker_hits == 1
    assert weak_rotation.marker_hits < engine.MIN_STRONG_ORIENTATION_MARKERS
    assert selected is source


def test_worker_selects_a_genuinely_rotated_ticket_with_robust_evidence(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        source = _orientation_candidate(
            engine,
            orientation_degrees=0,
            lines=[
                _ocr_line("noise", x=0.1, y=0.1, width=0.2, height=0.05),
                _ocr_line("invoice", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("amount", x=0.1, y=0.3, width=0.2, height=0.05),
            ],
        )
        rotated = _orientation_candidate(
            engine,
            orientation_degrees=90,
            lines=[
                _ocr_line("UNLOADING TICKET", x=0.1, y=0.1, width=0.4, height=0.05),
                _ocr_line("FACTORYNET", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("31.25", x=0.4, y=0.2, width=0.2, height=0.05),
                _ocr_line("GROSS", x=0.1, y=0.3, width=0.2, height=0.05),
            ],
            fields={
                "factory_net": {
                    "amount": "31.25",
                    "unit": "t",
                    "confidence": 0.99,
                }
            },
        )

        selected = engine._select_ocr_candidate((source, rotated))

    assert rotated.role_marker_hits >= 1
    assert rotated.marker_hits >= engine.MIN_STRONG_ORIENTATION_MARKERS
    assert selected is rotated


def test_worker_prefers_a_strong_rotation_over_a_marker_rich_but_weak_source(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        source = _orientation_candidate(
            engine,
            orientation_degrees=0,
            lines=[
                _ocr_line(
                    "装货 卸货 客户名称 提示信息 保存成功 工厂净重 称重来源",
                    x=0.1,
                    y=0.1,
                    width=0.7,
                    height=0.05,
                ),
                _ocr_line("garbage", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("garbage", x=0.1, y=0.3, width=0.2, height=0.05),
            ],
        )
        rotated = _orientation_candidate(
            engine,
            orientation_degrees=90,
            lines=[
                _ocr_line("UNLOADING TICKET", x=0.1, y=0.1, width=0.4, height=0.05),
                _ocr_line("FACTORYNET", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("31.25", x=0.4, y=0.2, width=0.2, height=0.05),
                _ocr_line("GROSS", x=0.1, y=0.3, width=0.2, height=0.05),
            ],
            fields={
                "factory_net": {
                    "amount": "31.25",
                    "unit": "t",
                    "confidence": 0.99,
                }
            },
        )

        selected = engine._select_ocr_candidate((source, rotated))

    assert not source.strong_orientation_signal
    assert rotated.strong_orientation_signal
    assert source.marker_hits > rotated.marker_hits
    assert selected is rotated


def test_worker_does_not_treat_one_keyword_stuffed_line_as_independent_evidence(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        stuffed = _orientation_candidate(
            engine,
            orientation_degrees=90,
            lines=[
                _ocr_line(
                    "UNLOADING TICKET FACTORYNET GROSS TARE NET",
                    x=0.1,
                    y=0.1,
                    width=0.8,
                    height=0.05,
                ),
                _ocr_line("garbage", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("garbage", x=0.1, y=0.3, width=0.2, height=0.05),
            ],
            fields={
                "factory_net": {
                    "amount": "31.25",
                    "unit": "t",
                    "confidence": 0.99,
                }
            },
        )

    assert stuffed.marker_hits >= engine.MIN_STRONG_ORIENTATION_MARKERS
    assert stuffed.supporting_marker_line_hits == 1
    assert not stuffed.strong_orientation_signal


@pytest.mark.parametrize(
    "text",
    [
        "UNLOADINGLY",
        "FACTORYNETWORK",
        "GROSSER",
    ],
)
def test_worker_does_not_match_english_markers_inside_larger_words(
    project_root: Path,
    text: str,
) -> None:
    lines = [
        _ocr_line(
            text,
            x=0.1,
            y=0.1,
            width=0.4,
            height=0.05,
        )
    ]

    with _worker_engine(project_root) as engine:
        evidence = engine._orientation_marker_evidence(lines)

    assert evidence.role_marker_hits == 0
    assert evidence.marker_hits == 0
    assert evidence.supporting_marker_line_hits == 0


def test_worker_matches_unloading_once_without_also_creating_loading(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        matches = engine._longest_matching_terms(
            "UNLOADING",
            engine.FIXED_TERMS,
        )

    assert matches == ("UNLOADING",)


@pytest.mark.parametrize(
    "text",
    [
        "UN-LOADING",
        "UN/LOADING",
        "UN_LOADING",
        "UN·LOADING",
        "UN—LOADING",
    ],
)
def test_worker_resolves_separator_split_unloading_without_emitting_loading(
    project_root: Path,
    text: str,
) -> None:
    with _worker_engine(project_root) as engine:
        matches = engine._longest_matching_terms(
            text,
            engine.FIXED_TERMS,
        )

    assert matches == ("UNLOADING",)


def test_worker_requires_lines_that_contribute_independent_marker_terms(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        repeated = _orientation_candidate(
            engine,
            orientation_degrees=90,
            lines=[
                _ocr_line(
                    "UNLOADING FACTORYNET GROSS",
                    x=0.1,
                    y=0.1,
                    width=0.6,
                    height=0.05,
                ),
                _ocr_line("GROSS", x=0.1, y=0.2, width=0.2, height=0.05),
                _ocr_line("GROSS", x=0.1, y=0.3, width=0.2, height=0.05),
            ],
            fields={
                "factory_net": {
                    "amount": "31.25",
                    "unit": "t",
                    "confidence": 0.99,
                }
            },
        )

    assert repeated.marker_hits >= engine.MIN_STRONG_ORIENTATION_MARKERS
    assert repeated.supporting_marker_line_hits == 3
    assert repeated.independent_marker_line_hits == 1
    assert not repeated.strong_orientation_signal


def test_worker_excludes_low_confidence_marker_hallucinations_from_role_output(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeImageArray:
        pass

    class FakePrediction:
        def __init__(self) -> None:
            self.json = {
                "res": {
                    "rec_texts": [
                        "UNLOADING TICKET",
                        "FACTORYNET",
                        "31.25",
                        "GROSS",
                        "LOADING",
                    ],
                    "rec_scores": [0.99, 0.98, 0.97, 0.96, 0.01],
                    "rec_boxes": [
                        [10, 10, 50, 20],
                        [10, 30, 30, 40],
                        [35, 30, 50, 40],
                        [10, 50, 30, 60],
                        [10, 70, 30, 80],
                    ],
                }
            }

    class FakePipeline:
        def predict(
            self,
            _image_array: FakeImageArray,
            **_options: object,
        ) -> list[FakePrediction]:
            return [FakePrediction()]

    with _worker_engine(project_root) as engine:
        monkeypatch.setattr(
            engine.PaddleEngine,
            "_decode_image",
            staticmethod(lambda _image_bytes: (FakeImageArray(), 100, 100)),
        )
        worker = engine.PaddleEngine(
            engine.EngineConfig(
                runtime_kind="cpu",
                current_device_index=None,
                models_dir=tmp_path,
                precision="fp32",
                batch_size=1,
                cpu_threads=1,
            )
        )
        worker._pipeline = FakePipeline()

        result = worker.extract(b"role-hallucination")

    assert [line["text"] for line in result["text_lines"]] == [
        "UNLOADING TICKET",
        "FACTORYNET",
        "31.25",
        "GROSS",
    ]
    assert "UNLOADING" in result["role_observation"]["fixed_text"]
    assert "LOADING" not in result["role_observation"]["fixed_text"]


def test_orientation_probe_dimensions_preserve_aspect_ratio_within_pixel_cap(
    project_root: Path,
) -> None:
    with _worker_engine(project_root) as engine:
        width, height = engine._orientation_probe_dimensions(
            width=10_000,
            height=8_000,
            max_pixels=8_000_000,
        )

    assert width * height <= 8_000_000
    assert width < 10_000
    assert height < 8_000
    assert width / height == pytest.approx(10_000 / 8_000, rel=0.001)


def test_large_image_uses_capped_orientation_probes_then_full_resolution_final_ocr(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeImageArray:
        def __init__(self, kind: str, correction_degrees: int) -> None:
            self.kind = kind
            self.correction_degrees = correction_degrees

    numpy = ModuleType("numpy")
    numpy.rot90 = lambda value, k: FakeImageArray(  # type: ignore[attr-defined]
        value.kind,
        (value.correction_degrees + (90 * k)) % 360,
    )
    numpy.ascontiguousarray = lambda value: value  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "numpy", numpy)

    calls: list[tuple[str, int]] = []
    resize_calls: list[tuple[int, int]] = []

    class FakePrediction:
        def __init__(self, payload: dict[str, object]) -> None:
            self.json = {"res": payload}

    def robust_payload(amount: str) -> dict[str, object]:
        return {
            "rec_texts": [
                "UNLOADING TICKET",
                "FACTORYNET",
                amount,
                "GROSS",
            ],
            "rec_scores": [0.99, 0.98, 0.97, 0.96],
            "rec_boxes": [
                [10, 10, 50, 20],
                [10, 30, 30, 40],
                [35, 30, 50, 40],
                [10, 50, 30, 60],
            ],
        }

    class FakePipeline:
        def predict(
            self,
            image_array: FakeImageArray,
            **_options: object,
        ) -> list[FakePrediction]:
            calls.append((image_array.kind, image_array.correction_degrees))
            if image_array.correction_degrees == 90:
                amount = "11.11" if image_array.kind == "probe" else "33.33"
                return [FakePrediction(robust_payload(amount))]
            return [
                FakePrediction(
                    {
                        "rec_texts": ["noise"],
                        "rec_scores": [0.99],
                        "rec_boxes": [[10, 10, 30, 20]],
                    }
                )
            ]

    def fake_resize(
        _image_array: FakeImageArray,
        *,
        width: int,
        height: int,
    ) -> tuple[FakeImageArray, int, int]:
        resize_calls.append((width, height))
        return FakeImageArray("probe", 0), 1000, 500

    with _worker_engine(project_root) as engine:
        monkeypatch.setattr(engine, "MAX_ORIENTATION_PROBE_PIXELS", 1_000_000, raising=False)
        monkeypatch.setattr(
            engine.PaddleEngine,
            "_decode_image",
            staticmethod(
                lambda _image_bytes: (
                    FakeImageArray("full", 0),
                    2000,
                    1000,
                )
            ),
        )
        monkeypatch.setattr(
            engine.PaddleEngine,
            "_resize_orientation_probe",
            staticmethod(fake_resize),
            raising=False,
        )
        worker = engine.PaddleEngine(
            engine.EngineConfig(
                runtime_kind="cpu",
                current_device_index=None,
                models_dir=tmp_path,
                precision="fp32",
                batch_size=1,
                cpu_threads=1,
            )
        )
        worker._pipeline = FakePipeline()

        result = worker.extract(b"large-rotated-image")

    assert resize_calls == [(2000, 1000)]
    assert calls == [
        ("full", 0),
        ("probe", 0),
        ("probe", 90),
        ("probe", 180),
        ("probe", 270),
        ("full", 90),
    ]
    assert result["role_observation"]["orientation_degrees"] == 90
    assert result["fields"]["factory_net"]["amount"] == "33.33"
    assert all(line["text"] != "11.11" for line in result["text_lines"])
