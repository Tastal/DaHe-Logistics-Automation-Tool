from __future__ import annotations

import re

_PROVINCE_PREFIXES = frozenset(
    "京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼"
)
_PLATE_TAIL = re.compile(r"[A-Z0-9学警港澳挂使领]{5,10}\Z")


def normalize_chengfeng_vehicle_number(value: str) -> str:
    """Repair only provable Chengfeng transport-decoding damage.

    Chengfeng has returned both GBK bytes decoded as Latin-1 and UTF-8 bytes
    decoded as GBK. The repair is deliberately limited to values that become
    a plausible Chinese vehicle number; unknown text is preserved verbatim.
    """

    if _looks_like_vehicle_number(value):
        return value
    for source_encoding, target_encoding in (
        ("latin-1", "gb18030"),
        ("gb18030", "utf-8"),
    ):
        try:
            candidate = value.encode(source_encoding).decode(target_encoding)
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        if _looks_like_vehicle_number(candidate):
            return candidate
    return value


def _looks_like_vehicle_number(value: str) -> bool:
    return (
        len(value) >= 6
        and value[0] in _PROVINCE_PREFIXES
        and _PLATE_TAIL.fullmatch(value[1:].upper()) is not None
    )
