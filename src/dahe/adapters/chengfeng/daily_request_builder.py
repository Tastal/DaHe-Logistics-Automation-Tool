from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from dahe.adapters.chengfeng.daily_manifest import (
    DAILY_LIST_OPERATION,
    DailyReadContractManifest,
)
from dahe.domain.daily.calendar import CandidateQueryWindow


class DailyRequestBuilderError(ValueError):
    """Raised when a daily read cannot be represented by the frozen contract."""


@dataclass(frozen=True, slots=True)
class DailyAuthorizedRequest:
    operation: str
    method: str
    url: str
    parameters_location: str
    parameters: Mapping[str, object] = field(repr=False)


class ChengfengDailyRequestBuilder:
    """Build one immutable request from business inputs plus a frozen empty baseline."""

    def __init__(self, manifest: DailyReadContractManifest) -> None:
        self._manifest = manifest

    def list_waybills(
        self,
        *,
        query_window: CandidateQueryWindow,
        receive_place: str,
        page_number: int,
        page_size: int,
    ) -> DailyAuthorizedRequest:
        if not isinstance(query_window, CandidateQueryWindow):
            raise DailyRequestBuilderError(
                "query window must be a validated candidate window"
            )
        if (
            type(receive_place) is not str
            or not receive_place
            or receive_place != receive_place.strip()
            or len(receive_place) > 100
            or any(ord(character) < 32 or ord(character) == 127 for character in receive_place)
            or "://" in receive_place
            or "?" in receive_place
            or "#" in receive_place
        ):
            raise DailyRequestBuilderError("receive place is invalid")
        if type(page_number) is not int or not 1 <= page_number <= 10_000:
            raise DailyRequestBuilderError("page number is outside the frozen bound")
        if type(page_size) is not int or not 1 <= page_size <= 100:
            raise DailyRequestBuilderError("page size is outside the frozen bound")

        controlled: dict[str, object] = {
            "loadStartTime": query_window.start.strftime("%Y-%m-%d %H:%M:%S"),
            "loadEndTime": query_window.end.strftime("%Y-%m-%d %H:%M:%S"),
            "receivePlace": receive_place,
            "pageNumber": page_number,
            "pageSize": page_size,
        }
        parameters: dict[str, object] = {}
        for name, rule in self._manifest.request_fields.items():
            if name in controlled:
                value = controlled[name]
            elif rule.type == "string":
                value = ""
            elif rule.type == "empty_array":
                value = ()
            elif rule.type == "null":
                value = None
            else:
                raise DailyRequestBuilderError(
                    "frozen baseline contains a nonempty field type"
                )
            parameters[name] = value

        return DailyAuthorizedRequest(
            operation=DAILY_LIST_OPERATION,
            method=self._manifest.method,
            url=f"{self._manifest.origin}{self._manifest.path}",
            parameters_location=self._manifest.parameters_location,
            parameters=MappingProxyType(parameters),
        )
