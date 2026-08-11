from __future__ import annotations

import hashlib
import json

from dahe.adapters.chengfeng.contract_freezer import (
    DETAIL_PATH,
    LIST_PATH,
)
from dahe.adapters.chengfeng.live_manifest import (
    LiveAuthorizedRequest,
    LiveReadContractManifest,
    LiveReadDeclaration,
    LiveReadOnlyRequestFirewall,
)
from dahe.adapters.chengfeng.policy import ReadRequest, RequestDeniedError
from dahe.ports.chengfeng import APPROVED_SETTLEMENT_SCOPES

# The firewall requires every frozen field to be present. The browser Worker
# replaces these three placeholders with a validated official-page baseline
# before any request can reach Chengfeng.
_LIST_PROTOCOL_PLACEHOLDERS: dict[str, str | int] = {
    "order": "desc",
    "queryType": "",
    "settleQueryType": 1,
}
HISTORICAL_SETTLED_LIST_PATH = (
    "/api/order-center-server/app/clientOrderItem/"
    "queryClientAllFinishSettlementOrderItemListPC"
)
_HISTORICAL_LIST_RESPONSE_FIELDS = (
    ("$.data.list[].carNumber", ("string",)),
    ("$.data.list[].orderItemId", ("string",)),
    ("$.data.list[].orderItemSn", ("string",)),
    ("$.data.total", ("string",)),
)


class LiveRequestBuilderError(RuntimeError):
    """Raised when a logical read cannot map to the frozen network contract."""


class ChengfengLiveRequestBuilder:
    """Build the only two direct network requests permitted by Loop 9."""

    def __init__(self, manifest: LiveReadContractManifest) -> None:
        self._manifest = manifest
        self._firewall = LiveReadOnlyRequestFirewall(manifest)
        self._list = self._declaration("list_waybills", LIST_PATH)
        self._detail = self._declaration("get_waybill_detail", DETAIL_PATH)
        self._historical_manifest = _historical_settled_manifest(manifest)
        self._historical_firewall = LiveReadOnlyRequestFirewall(
            self._historical_manifest
        )

    def list_waybills(
        self,
        *,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> LiveAuthorizedRequest:
        if scope not in APPROVED_SETTLEMENT_SCOPES:
            raise LiveRequestBuilderError(
                "the settlement scope is not approved"
            )
        if scope == "settled_history":
            return self._authorize_historical(
                ReadRequest(
                    operation="list_waybills",
                    method="POST",
                    url=(
                        f"{self._manifest.origin}"
                        f"{HISTORICAL_SETTLED_LIST_PATH}"
                    ),
                    parameters_location="json",
                    parameters={
                        "deptCode": "",
                        "pageNumber": page_number,
                        "pageSize": page_size,
                        "sortParams": [],
                    },
                )
            )
        parameters: dict[str, object] = {}
        for name, rule in self._list.parameters.items():
            if name == "pageNumber":
                value: object = page_number
            elif name == "pageSize":
                value = page_size
            elif name in _LIST_PROTOCOL_PLACEHOLDERS:
                value = _LIST_PROTOCOL_PLACEHOLDERS[name]
            elif rule.type == "empty_list":
                value = []
            elif rule.type == "string":
                value = ""
            else:
                raise LiveRequestBuilderError(
                    "the frozen list contract contains an unsupported integer"
                )
            parameters[name] = value
        return self._authorize(
            ReadRequest(
                operation="list_waybills",
                method="POST",
                url=f"{self._manifest.origin}{self._list.path}",
                parameters_location="json",
                parameters=parameters,
            )
        )

    def get_waybill_detail(self, *, platform_waybill_id: str) -> LiveAuthorizedRequest:
        if (
            not platform_waybill_id
            or len(platform_waybill_id) > 64
            or not platform_waybill_id.isascii()
            or not platform_waybill_id.isdigit()
        ):
            raise LiveRequestBuilderError("platform waybill identity is invalid")
        if set(self._detail.parameters) != {"id"}:
            raise LiveRequestBuilderError("the frozen detail contract identity changed")
        if self._detail.parameters_location != "form":
            raise LiveRequestBuilderError(
                "the frozen detail contract uses a historical encoding"
            )
        return self._authorize(
            ReadRequest(
                operation="get_waybill_detail",
                method="POST",
                url=f"{self._manifest.origin}{self._detail.path}",
                parameters_location="form",
                parameters={"id": platform_waybill_id},
            )
        )

    def _declaration(self, operation: str, expected_path: str) -> LiveReadDeclaration:
        matches = tuple(
            request
            for request in self._manifest.requests
            if request.operation == operation
        )
        if len(matches) != 1 or matches[0].path != expected_path:
            raise LiveRequestBuilderError("the frozen read operation path changed")
        return matches[0]

    def _authorize(self, request: ReadRequest) -> LiveAuthorizedRequest:
        try:
            return self._firewall.authorize(request)
        except RequestDeniedError as exc:
            raise LiveRequestBuilderError("logical read was denied by the contract") from exc

    def _authorize_historical(
        self,
        request: ReadRequest,
    ) -> LiveAuthorizedRequest:
        try:
            return self._historical_firewall.authorize(request)
        except RequestDeniedError as exc:
            raise LiveRequestBuilderError(
                "historical logical read was denied by the contract"
            ) from exc


def _historical_settled_manifest(
    manifest: LiveReadContractManifest,
) -> LiveReadContractManifest:
    """Derive the fixed historical list surface from the selected read contract."""

    document = manifest.canonical_document
    requests = document.get("requests")
    if (
        not isinstance(requests, list)
        or not requests
        or not isinstance(requests[0], dict)
    ):
        raise LiveRequestBuilderError(
            "the selected contract cannot derive a historical list"
        )
    list_request = requests[0]
    list_request["path"] = HISTORICAL_SETTLED_LIST_PATH
    list_request["parameters"] = {
        "deptCode": {
            "type": "string",
            "constant": None,
            "minimum": None,
            "maximum": None,
            "allow_empty": True,
        },
        "pageNumber": {
            "type": "integer",
            "constant": None,
            "minimum": 1,
            "maximum": 10_000,
            "allow_empty": False,
        },
        "pageSize": {
            "type": "integer",
            "constant": None,
            "minimum": 1,
            "maximum": 100,
            "allow_empty": False,
        },
        "sortParams": {
            "type": "empty_list",
            "constant": None,
            "minimum": None,
            "maximum": None,
            "allow_empty": False,
        },
    }
    list_request["response_fields"] = [
        {"path": path, "types": list(types)}
        for path, types in _HISTORICAL_LIST_RESPONSE_FIELDS
    ]
    lineage = json.dumps(
        {
            "contract_kind": "loop9_historical_settled_list",
            "parent_contract_sha256": manifest.canonical_sha256,
            "path": HISTORICAL_SETTLED_LIST_PATH,
            "parameters": list_request["parameters"],
            "response_fields": list_request["response_fields"],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    document["source_discovery_sha256"] = hashlib.sha256(lineage).hexdigest()
    document["source_observation_count"] = 1
    return LiveReadContractManifest.model_validate_json(
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        strict=True,
    )
