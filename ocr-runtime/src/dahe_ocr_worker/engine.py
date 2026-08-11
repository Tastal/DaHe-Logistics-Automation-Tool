from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import os
import re
import sys
import time
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from dahe_ocr_worker.protocol import WorkerProtocolViolation

MAX_IMAGE_PIXELS = 80_000_000
MAX_ORIENTATION_PROBE_PIXELS = 8_000_000
MAX_TEXT_LINES = 2000
MAX_TEXT_LINE_CHARS = 2048
MAX_TOTAL_TEXT_CHARS = 256_000

WEIGHT_NUMBER = re.compile(r"(?<![0-9])([0-9]{1,6}(?:\.[0-9]{1,3})?)(?![0-9])")
WEIGHT_VALUE_LINE = re.compile(
    r"^\s*([0-9]{1,6}(?:\.[0-9]{1,3})?)\s*(kg|t|吨|千克|公斤)?\s*$",
    re.IGNORECASE,
)
FIELD_LABELS = {
    "ordinary_net": ("净重", "NETWEIGHT", "NET"),
    "factory_net": ("工厂净重", "FACTORYNET"),
    "gross": ("毛重", "GROSS"),
    "tare": ("皮重", "TARE"),
}
FIXED_TERMS = (
    "装货",
    "卸货",
    "磅单",
    "毛重",
    "皮重",
    "净重",
    "LOADING",
    "UNLOADING",
    "TICKET",
    "GROSS",
    "TARE",
    "NET",
)
ORIENTATION_ROLE_TERMS = (
    "装货",
    "卸货",
    "客户名称",
    "提示信息",
    "保存成功",
    "工厂净重",
    "称重来源",
    "LOADING",
    "UNLOADING",
    "FACTORYNET",
)
ORIENTATION_MARKER_TERMS = tuple(
    dict.fromkeys(
        (
            *FIXED_TERMS,
            *ORIENTATION_ROLE_TERMS,
        )
    )
)
SUPPORTED_ORIENTATIONS = (0, 90, 180, 270)
MIN_ORIENTATION_MARKER_CONFIDENCE = 0.75
MIN_STRONG_ORIENTATION_MARKERS = 3
MIN_STRONG_ORIENTATION_INDEPENDENT_LINES = 3
MIN_HORIZONTAL_TEXT_RATIO = 0.5
ASCII_OCR_SEPARATOR_PATTERN = (
    "[\\s_./\\\\\\u00b7\\u2022:\\uff1a|\\u2010\\u2011\\u2012\\u2013\\u2014\\u2212-]*"
)


@dataclass(frozen=True, slots=True)
class EngineConfig:
    runtime_kind: str
    current_device_index: int | None
    models_dir: Path
    precision: str
    batch_size: int
    cpu_threads: int

    @property
    def paddle_device(self) -> str:
        if self.runtime_kind == "cpu":
            return "cpu"
        if self.current_device_index is None:
            raise RuntimeError("GPU runtime has no current device mapping")
        return f"gpu:{self.current_device_index}"


@dataclass(frozen=True, slots=True)
class _OcrCandidate:
    orientation_degrees: int
    canonical_lines: list[dict[str, Any]]
    source_lines: list[dict[str, Any]]
    canonical_fields: dict[str, dict[str, Any]]
    role_marker_hits: int
    marker_hits: int
    confidence_total: float
    text_characters: int
    horizontal_text_ratio: float
    supporting_marker_line_hits: int = 0
    independent_marker_line_hits: int = 0

    @property
    def strong_orientation_signal(self) -> bool:
        return (
            self.role_marker_hits >= 1
            and self.marker_hits >= MIN_STRONG_ORIENTATION_MARKERS
            and self.independent_marker_line_hits >= MIN_STRONG_ORIENTATION_INDEPENDENT_LINES
            and bool(self.canonical_fields)
            and len(self.canonical_lines) >= 3
            and self.horizontal_text_ratio >= MIN_HORIZONTAL_TEXT_RATIO
        )

    @property
    def rank(self) -> tuple[int, int, int, int, int, float, float, int, int, int]:
        return (
            self.role_marker_hits,
            self.independent_marker_line_hits,
            self.supporting_marker_line_hits,
            self.marker_hits,
            len(self.canonical_fields),
            self.horizontal_text_ratio,
            self.confidence_total,
            self.text_characters,
            len(self.canonical_lines),
            -self.orientation_degrees,
        )


def _select_ocr_candidate(
    candidates: Sequence[_OcrCandidate],
) -> _OcrCandidate:
    if not candidates:
        raise RuntimeError("OCR orientation search returned no candidate")
    source = next(
        (candidate for candidate in candidates if candidate.orientation_degrees == 0),
        None,
    )
    if source is None:
        raise RuntimeError("OCR orientation search omitted the source orientation")
    robust_rotations = tuple(
        candidate
        for candidate in candidates
        if candidate.orientation_degrees != 0 and candidate.strong_orientation_signal
    )
    if not robust_rotations:
        return source
    if not source.strong_orientation_signal:
        return max(robust_rotations, key=lambda candidate: candidate.rank)
    return max((source, *robust_rotations), key=lambda candidate: candidate.rank)


@dataclass(frozen=True, slots=True)
class _OrientationMarkerEvidence:
    role_marker_hits: int
    marker_hits: int
    supporting_marker_line_hits: int
    independent_marker_line_hits: int


def _term_matches(text: str, term: str) -> bool:
    normalized_term = re.sub(r"\s+", "", term).upper()
    if normalized_term.isascii() and normalized_term.isalnum():
        flexible_term = ASCII_OCR_SEPARATOR_PATTERN.join(
            re.escape(character) for character in normalized_term
        )
        return (
            re.search(
                rf"(?<![A-Z0-9]){flexible_term}(?![A-Z0-9])",
                text.upper(),
            )
            is not None
        )
    normalized_text = re.sub(r"\s+", "", text).upper()
    return normalized_term in normalized_text


def _longest_matching_terms(
    text: str,
    terms: Sequence[str],
) -> tuple[str, ...]:
    matched = tuple(
        (term, re.sub(r"\s+", "", term).upper()) for term in terms if _term_matches(text, term)
    )
    return tuple(
        term
        for term, normalized_term in matched
        if not any(
            normalized_term != other_normalized and normalized_term in other_normalized
            for _, other_normalized in matched
        )
    )


def _orientation_marker_evidence(
    lines: Sequence[dict[str, Any]],
) -> _OrientationMarkerEvidence:
    role_terms: set[str] = set()
    marker_terms: set[str] = set()
    supporting_marker_line_hits = 0
    independent_marker_line_hits = 0
    for line in lines:
        confidence = float(line["confidence"])
        if not math.isfinite(confidence) or confidence < MIN_ORIENTATION_MARKER_CONFIDENCE:
            continue
        text = str(line["text"])
        line_role_terms = _longest_matching_terms(text, ORIENTATION_ROLE_TERMS)
        line_marker_terms = _longest_matching_terms(text, ORIENTATION_MARKER_TERMS)
        role_terms.update(line_role_terms)
        if line_marker_terms:
            supporting_marker_line_hits += 1
        if set(line_marker_terms) - marker_terms:
            independent_marker_line_hits += 1
        marker_terms.update(line_marker_terms)
    return _OrientationMarkerEvidence(
        role_marker_hits=len(role_terms),
        marker_hits=len(marker_terms),
        supporting_marker_line_hits=supporting_marker_line_hits,
        independent_marker_line_hits=independent_marker_line_hits,
    )


def _orientation_marker_hits(
    lines: Sequence[dict[str, Any]],
) -> tuple[int, int]:
    evidence = _orientation_marker_evidence(lines)
    return evidence.role_marker_hits, evidence.marker_hits


def _role_safe_lines(
    lines: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        line
        for line in lines
        if not (
            float(line["confidence"]) < MIN_ORIENTATION_MARKER_CONFIDENCE
            and _longest_matching_terms(
                str(line["text"]),
                ORIENTATION_MARKER_TERMS,
            )
        )
    ]


def _orientation_probe_dimensions(
    *,
    width: int,
    height: int,
    max_pixels: int,
) -> tuple[int, int]:
    if width <= 0 or height <= 0 or max_pixels <= 0:
        raise RuntimeError("orientation probe dimensions must be positive")
    if width * height <= max_pixels:
        return width, height
    scale = math.sqrt(max_pixels / (width * height))
    probe_width = max(1, math.floor(width * scale))
    probe_height = max(1, math.floor(height * scale))
    while probe_width * probe_height > max_pixels:
        if probe_width >= probe_height:
            probe_width -= 1
        else:
            probe_height -= 1
    return probe_width, probe_height


def _validated_prediction_arrays(
    payload: dict[str, Any],
) -> tuple[list[Any], list[Any], list[Any]]:
    arrays: list[list[Any]] = []
    for field_name in ("rec_texts", "rec_scores", "rec_boxes"):
        value = payload.get(field_name, [])
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise RuntimeError("PaddleOCR prediction arrays are not aligned sequences")
        arrays.append(list(value))
    texts, scores, boxes = arrays
    if not (len(texts) == len(scores) == len(boxes)):
        raise RuntimeError("PaddleOCR prediction arrays are not aligned")
    if len(texts) > MAX_TEXT_LINES:
        raise RuntimeError("PaddleOCR returned too many text lines")
    return texts, scores, boxes


def _normalized_box(
    *,
    left: float,
    top: float,
    right: float,
    bottom: float,
    image_width: int,
    image_height: int,
) -> dict[str, float]:
    """Return bounded coordinates that remain valid after JSON decimal parsing."""

    if image_width <= 0 or image_height <= 0:
        raise RuntimeError("PaddleOCR text box has invalid image dimensions")
    if not all(math.isfinite(value) for value in (left, top, right, bottom)):
        raise RuntimeError("PaddleOCR returned a non-finite text box")
    if right <= left or bottom <= top:
        raise RuntimeError("PaddleOCR returned a non-positive text box")

    clipped_left = max(0.0, min(float(image_width), left))
    clipped_top = max(0.0, min(float(image_height), top))
    clipped_right = max(0.0, min(float(image_width), right))
    clipped_bottom = max(0.0, min(float(image_height), bottom))
    if clipped_right <= clipped_left or clipped_bottom <= clipped_top:
        raise RuntimeError("PaddleOCR returned a text box outside the image")

    def normalized_axis(
        start: float,
        end: float,
        extent: int,
    ) -> tuple[float, float]:
        epsilon = 0.000001
        normalized_start = round(
            max(0.0, min(1.0 - epsilon, start / extent)),
            9,
        )
        normalized_end = round(
            max(
                normalized_start + epsilon,
                min(1.0, end / extent),
            ),
            9,
        )
        normalized_end = min(
            1.0,
            max(normalized_start + epsilon, normalized_end),
        )
        span = round(normalized_end - normalized_start, 9)

        decimal_start = Decimal(str(normalized_start))
        decimal_span = Decimal(str(span))
        if decimal_start + decimal_span > 1:
            span = float(Decimal(1) - decimal_start)
        if span <= 0:
            raise RuntimeError("PaddleOCR returned an empty text box")
        return normalized_start, span

    normalized_left, normalized_width = normalized_axis(
        clipped_left,
        clipped_right,
        image_width,
    )
    normalized_top, normalized_height = normalized_axis(
        clipped_top,
        clipped_bottom,
        image_height,
    )
    return {
        "x": normalized_left,
        "y": normalized_top,
        "width": normalized_width,
        "height": normalized_height,
    }


def _rotate_normalized_box(
    box: dict[str, float],
    orientation_degrees: int,
) -> dict[str, float]:
    if orientation_degrees not in SUPPORTED_ORIENTATIONS:
        raise RuntimeError("OCR orientation is unsupported")
    x = Decimal(str(box["x"]))
    y = Decimal(str(box["y"]))
    width = Decimal(str(box["width"]))
    height = Decimal(str(box["height"]))
    one = Decimal(1)
    if orientation_degrees == 0:
        rotated = x, y, width, height
    elif orientation_degrees == 90:
        rotated = one - y - height, x, height, width
    elif orientation_degrees == 180:
        rotated = one - x - width, one - y - height, width, height
    else:
        rotated = y, one - x - width, height, width
    return {
        name: round(float(value), 9)
        for name, value in zip(
            ("x", "y", "width", "height"),
            rotated,
            strict=True,
        )
    }


class PaddleEngine:
    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        self._pipeline: Any | None = None

    @staticmethod
    def _add_cuda_dll_directories() -> None:
        if os.name != "nt" or not hasattr(os, "add_dll_directory"):
            return
        site_packages = Path(sys.prefix) / "Lib" / "site-packages"
        candidates = (
            site_packages / "nvidia" / "cu13" / "bin" / "x86_64",
            site_packages / "nvidia" / "cudnn" / "bin",
        )
        for candidate in candidates:
            if candidate.is_dir():
                os.add_dll_directory(os.fspath(candidate))
                os.environ["PATH"] = os.fspath(candidate) + os.pathsep + os.environ.get("PATH", "")

    def _load_pipeline(self) -> Any:
        if self._pipeline is not None:
            return self._pipeline
        os.environ["PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK"] = "True"
        os.environ["PADDLE_PDX_DISABLE_DEVICE_FALLBACK"] = "True"
        self._add_cuda_dll_directories()
        with contextlib.redirect_stdout(sys.stderr):
            from paddleocr import PaddleOCR

            self._pipeline = PaddleOCR(
                text_detection_model_name="PP-OCRv6_medium_det",
                text_detection_model_dir=os.fspath(self.config.models_dir / "PP-OCRv6_medium_det"),
                text_recognition_model_name="PP-OCRv6_medium_rec",
                text_recognition_model_dir=os.fspath(
                    self.config.models_dir / "PP-OCRv6_medium_rec"
                ),
                use_doc_orientation_classify=False,
                use_doc_unwarping=False,
                use_textline_orientation=False,
                text_recognition_batch_size=self.config.batch_size,
                text_rec_score_thresh=0.0,
                text_det_limit_side_len=1600,
                text_det_limit_type="max",
                device=self.config.paddle_device,
                cpu_threads=self.config.cpu_threads,
                # Paddle 3.3.1 cannot execute the PP-OCRv6 PIR model through
                # oneDNN on Windows. Keep the portable CPU fallback conservative.
                enable_mkldnn=False,
                precision=self.config.precision,
                enable_hpi=False,
                use_tensorrt=False,
            )
        return self._pipeline

    @staticmethod
    def _payload(result: Any) -> dict[str, Any]:
        payload = result.json
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            raise RuntimeError("PaddleOCR returned a non-object result")
        nested = payload.get("res", payload)
        if not isinstance(nested, dict):
            raise RuntimeError("PaddleOCR result payload is invalid")
        return nested

    @staticmethod
    def _decode_image(image_bytes: bytes) -> tuple[Any, int, int]:
        """Decode the already-hashed snapshot without reopening its source path."""
        import numpy as np
        from PIL import Image, ImageOps

        def decode(captured: bytes) -> tuple[Any, int, int]:
            with warnings.catch_warnings():
                warnings.simplefilter(
                    "error",
                    Image.DecompressionBombWarning,
                )
                with Image.open(io.BytesIO(captured)) as source:
                    source_width, source_height = source.size
                    if (
                        source_width <= 0
                        or source_height <= 0
                        or source_width * source_height
                        > MAX_IMAGE_PIXELS
                    ):
                        raise WorkerProtocolViolation(
                            "image dimensions exceed the safe pixel limit"
                        )
                    source.load()
                    with ImageOps.exif_transpose(source) as oriented:
                        width, height = oriented.size
                        with oriented.convert("RGB") as rgb:
                            image_array = np.ascontiguousarray(
                                np.asarray(rgb)
                            )
            return image_array, width, height

        try:
            return decode(image_bytes)
        except OSError as exc:
            missing_jpeg_end_marker = (
                image_bytes.startswith(b"\xff\xd8")
                and not image_bytes.endswith(b"\xff\xd9")
                and str(exc).startswith("image file is truncated")
            )
            if not missing_jpeg_end_marker:
                raise
            # Preserve and hash the original evidence bytes. Chengfeng has
            # returned otherwise-decodable JPEG payloads without the final
            # EOI marker; repair only the in-memory decoder input.
            return decode(image_bytes + b"\xff\xd9")

    @staticmethod
    def _rotate_image_for_ocr(image_array: Any, orientation_degrees: int) -> Any:
        if orientation_degrees not in SUPPORTED_ORIENTATIONS:
            raise RuntimeError("OCR orientation is unsupported")
        if orientation_degrees == 0:
            return image_array
        import numpy as np

        return np.ascontiguousarray(np.rot90(image_array, k=orientation_degrees // 90))

    @staticmethod
    def _resize_orientation_probe(
        image_array: Any,
        *,
        width: int,
        height: int,
    ) -> tuple[Any, int, int]:
        probe_width, probe_height = _orientation_probe_dimensions(
            width=width,
            height=height,
            max_pixels=MAX_ORIENTATION_PROBE_PIXELS,
        )
        if (probe_width, probe_height) == (width, height):
            return image_array, width, height

        import numpy as np
        from PIL import Image

        with (
            Image.fromarray(image_array) as source,
            source.resize(
                (probe_width, probe_height),
                resample=Image.Resampling.LANCZOS,
                reducing_gap=3.0,
            ) as resized,
        ):
            probe_array = np.ascontiguousarray(np.asarray(resized))
        return probe_array, probe_width, probe_height

    @staticmethod
    def _oriented_dimensions(
        width: int,
        height: int,
        orientation_degrees: int,
    ) -> tuple[int, int]:
        if orientation_degrees not in SUPPORTED_ORIENTATIONS:
            raise RuntimeError("OCR orientation is unsupported")
        if orientation_degrees in {90, 270}:
            return height, width
        return width, height

    @staticmethod
    def _parse_fields(lines: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        fields: dict[str, dict[str, Any]] = {}
        factory_labels = FIELD_LABELS["factory_net"]

        def contains_label(
            field: str,
            text: str,
            labels: tuple[str, ...],
        ) -> bool:
            if field == "ordinary_net" and _longest_matching_terms(
                text,
                factory_labels,
            ):
                return False
            return bool(_longest_matching_terms(text, labels))

        def unit_for(*texts: str) -> str:
            normalized = " ".join(texts).upper()
            return "kg" if any(term in normalized for term in ("KG", "千克", "公斤")) else "t"

        def field_payload(
            *,
            amount_text: str,
            raw_text: str,
            label_text: str,
            confidence: float,
        ) -> dict[str, Any] | None:
            try:
                amount = Decimal(amount_text)
            except InvalidOperation:
                return None
            if not amount.is_finite():
                return None
            return {
                "raw_text": raw_text,
                "amount": str(amount),
                "unit": unit_for(label_text, raw_text),
                "confidence": confidence,
            }

        def spatial_value(
            label_index: int,
        ) -> tuple[str, str, float] | None:
            label_line = lines[label_index]
            label_box = label_line["box"]
            label_x = float(label_box["x"])
            label_y = float(label_box["y"])
            label_width = float(label_box["width"])
            label_height = float(label_box["height"])
            label_right = label_x + label_width
            label_center_y = label_y + (label_height / 2)
            candidates: list[tuple[tuple[float, float, float, int], str, str, float]] = []
            for candidate_index, candidate_line in enumerate(lines):
                if candidate_index == label_index:
                    continue
                candidate_text = str(candidate_line["text"])
                match = WEIGHT_VALUE_LINE.fullmatch(candidate_text)
                if match is None:
                    continue
                candidate_box = candidate_line["box"]
                candidate_x = float(candidate_box["x"])
                candidate_y = float(candidate_box["y"])
                candidate_height = float(candidate_box["height"])
                candidate_center_y = candidate_y + (candidate_height / 2)
                vertical_scale = max(label_height, candidate_height)
                vertical_distance = abs(label_center_y - candidate_center_y)
                horizontal_gap = candidate_x - label_right
                if (
                    vertical_scale <= 0
                    or vertical_distance > vertical_scale * 0.65
                    or horizontal_gap < -0.01
                    or horizontal_gap > 0.40
                ):
                    continue
                confidence = min(
                    float(label_line["confidence"]),
                    float(candidate_line["confidence"]),
                )
                candidates.append(
                    (
                        (
                            vertical_distance / vertical_scale,
                            max(0.0, horizontal_gap),
                            -confidence,
                            candidate_index,
                        ),
                        match.group(1),
                        candidate_text,
                        confidence,
                    )
                )
            if not candidates:
                return None
            _, amount_text, raw_text, confidence = min(
                candidates,
                key=lambda item: item[0],
            )
            return amount_text, raw_text, confidence

        for field, labels in FIELD_LABELS.items():
            for index, line in enumerate(lines):
                raw_text = str(line["text"])
                if not contains_label(field, raw_text, labels):
                    continue
                numbers = WEIGHT_NUMBER.findall(raw_text)
                if numbers:
                    payload = field_payload(
                        amount_text=numbers[-1],
                        raw_text=raw_text,
                        label_text=raw_text,
                        confidence=float(line["confidence"]),
                    )
                else:
                    spatial = spatial_value(index)
                    payload = (
                        None
                        if spatial is None
                        else field_payload(
                            amount_text=spatial[0],
                            raw_text=spatial[1],
                            label_text=raw_text,
                            confidence=spatial[2],
                        )
                    )
                if payload is not None:
                    fields[field] = payload
                    break
        return fields

    @staticmethod
    def _role_observation(
        lines: list[dict[str, Any]],
        *,
        orientation_degrees: int,
    ) -> dict[str, Any]:
        fixed: list[str] = []
        layout_parts: list[object] = []
        for line in _role_safe_lines(lines):
            text = str(line["text"])
            normalized = re.sub(r"\s+", "", text).upper()
            fixed.extend(_longest_matching_terms(text, FIXED_TERMS))
            layout_parts.append((normalized, line["box"]))
        layout_fingerprint = hashlib.sha256(
            json.dumps(
                layout_parts,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return {
            "fixed_text": sorted(set(fixed)),
            "layout_fingerprint": layout_fingerprint,
            "orientation_degrees": orientation_degrees,
        }

    def _predict_lines(
        self,
        *,
        pipeline: Any,
        image_array: Any,
        width: int,
        height: int,
    ) -> list[dict[str, Any]]:
        with contextlib.redirect_stdout(sys.stderr):
            predictions = list(
                pipeline.predict(
                    image_array,
                    use_doc_orientation_classify=False,
                    use_doc_unwarping=False,
                    use_textline_orientation=False,
                    text_det_limit_side_len=1600,
                    text_det_limit_type="max",
                )
            )
        if len(predictions) != 1:
            raise RuntimeError("PaddleOCR did not return exactly one image result")
        payload = self._payload(predictions[0])
        texts, scores, boxes = _validated_prediction_arrays(payload)
        lines: list[dict[str, Any]] = []
        total_text_chars = 0
        for text, score, box in zip(texts, scores, boxes, strict=True):
            if not isinstance(text, str):
                raise RuntimeError("PaddleOCR returned a non-text recognition value")
            if not text.strip():
                continue
            if len(text) > MAX_TEXT_LINE_CHARS:
                raise RuntimeError("PaddleOCR returned an oversized text line")
            total_text_chars += len(text)
            if total_text_chars > MAX_TOTAL_TEXT_CHARS:
                raise RuntimeError("PaddleOCR returned oversized aggregate text")
            if (
                not isinstance(box, Sequence)
                or isinstance(box, (str, bytes, bytearray))
                or len(box) != 4
            ):
                raise RuntimeError("PaddleOCR returned an invalid text box")
            left, top, right, bottom = (float(value) for value in box)
            normalized_box = _normalized_box(
                left=left,
                top=top,
                right=right,
                bottom=bottom,
                image_width=width,
                image_height=height,
            )
            confidence = float(score)
            if not math.isfinite(confidence):
                raise RuntimeError("PaddleOCR returned a non-finite recognition score")
            if confidence < 0.0 or confidence > 1.0:
                raise RuntimeError("PaddleOCR recognition score is outside [0, 1]")
            lines.append(
                {
                    "text": str(text),
                    "confidence": confidence,
                    "box": normalized_box,
                }
            )
        return lines

    def _candidate(
        self,
        *,
        pipeline: Any,
        source_image_array: Any,
        source_width: int,
        source_height: int,
        orientation_degrees: int,
    ) -> _OcrCandidate:
        image_array = self._rotate_image_for_ocr(
            source_image_array,
            orientation_degrees,
        )
        width, height = self._oriented_dimensions(
            source_width,
            source_height,
            orientation_degrees,
        )
        canonical_lines = self._predict_lines(
            pipeline=pipeline,
            image_array=image_array,
            width=width,
            height=height,
        )
        source_lines = [
            {
                **line,
                "box": _rotate_normalized_box(
                    line["box"],
                    orientation_degrees,
                ),
            }
            for line in canonical_lines
        ]
        marker_evidence = _orientation_marker_evidence(canonical_lines)
        informative_lines = [
            line for line in canonical_lines if len(re.sub(r"\s+", "", str(line["text"]))) >= 2
        ]
        horizontal_lines = sum(
            1
            for line in informative_lines
            if (float(line["box"]["width"]) * width >= float(line["box"]["height"]) * height)
        )
        return _OcrCandidate(
            orientation_degrees=orientation_degrees,
            canonical_lines=canonical_lines,
            source_lines=source_lines,
            canonical_fields=self._parse_fields(canonical_lines),
            role_marker_hits=marker_evidence.role_marker_hits,
            marker_hits=marker_evidence.marker_hits,
            confidence_total=sum(float(line["confidence"]) for line in canonical_lines),
            text_characters=sum(len(str(line["text"])) for line in canonical_lines),
            horizontal_text_ratio=(
                horizontal_lines / len(informative_lines) if informative_lines else 0.0
            ),
            supporting_marker_line_hits=marker_evidence.supporting_marker_line_hits,
            independent_marker_line_hits=marker_evidence.independent_marker_line_hits,
        )

    def extract(self, image_bytes: bytes) -> dict[str, Any]:
        started = time.perf_counter()
        image_array, width, height = self._decode_image(image_bytes)
        pipeline = self._load_pipeline()
        first = self._candidate(
            pipeline=pipeline,
            source_image_array=image_array,
            source_width=width,
            source_height=height,
            orientation_degrees=0,
        )
        selected = first
        if not first.strong_orientation_signal:
            if width * height > MAX_ORIENTATION_PROBE_PIXELS:
                probe_array, probe_width, probe_height = self._resize_orientation_probe(
                    image_array,
                    width=width,
                    height=height,
                )
                probe_candidates = tuple(
                    self._candidate(
                        pipeline=pipeline,
                        source_image_array=probe_array,
                        source_width=probe_width,
                        source_height=probe_height,
                        orientation_degrees=orientation,
                    )
                    for orientation in SUPPORTED_ORIENTATIONS
                )
                probe_selected = _select_ocr_candidate(probe_candidates)
                selected_orientation = probe_selected.orientation_degrees
                del probe_array, probe_candidates
                if selected_orientation != 0:
                    full_resolution_rotation = self._candidate(
                        pipeline=pipeline,
                        source_image_array=image_array,
                        source_width=width,
                        source_height=height,
                        orientation_degrees=selected_orientation,
                    )
                    selected = _select_ocr_candidate(
                        (first, full_resolution_rotation),
                    )
            else:
                candidates = [
                    first,
                    *(
                        self._candidate(
                            pipeline=pipeline,
                            source_image_array=image_array,
                            source_width=width,
                            source_height=height,
                            orientation_degrees=orientation,
                        )
                        for orientation in SUPPORTED_ORIENTATIONS[1:]
                    ),
                ]
                selected = _select_ocr_candidate(candidates)
        public_lines = _role_safe_lines(selected.source_lines)
        return {
            "elapsed_ms": (time.perf_counter() - started) * 1000,
            "text_lines": public_lines,
            "fields": selected.canonical_fields,
            "role_observation": self._role_observation(
                public_lines,
                orientation_degrees=selected.orientation_degrees,
            ),
        }
