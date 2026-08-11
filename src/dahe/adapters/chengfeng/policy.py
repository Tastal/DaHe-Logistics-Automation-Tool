from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import SplitResult, urlsplit

from dahe.adapters.chengfeng.manifest import FrozenContractManifest, FrozenRequest


class RequestDeniedError(RuntimeError):
    """Raised when a request is not an exact frozen read operation."""


@dataclass(frozen=True, slots=True)
class ReadRequest:
    """An untrusted request intent presented to the read-only firewall."""

    operation: str
    method: str
    url: str
    parameters_location: str
    parameters: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class AuthorizedRequest:
    """A request paired with the one exact manifest declaration that allowed it."""

    request: ReadRequest
    contract_request: FrozenRequest

    @property
    def operation(self) -> str:
        return self.request.operation

    @property
    def method(self) -> str:
        return self.request.method

    @property
    def url(self) -> str:
        return self.request.url

    @property
    def parameters_location(self) -> str:
        return self.request.parameters_location

    @property
    def parameters(self) -> Mapping[str, object]:
        return self.request.parameters


@dataclass(frozen=True, slots=True)
class _NormalizedOrigin:
    scheme: str
    hostname: str
    effective_port: int


class ReadOnlyRequestFirewall:
    """Authorize only exact manifest-declared reads and reject every redirect."""

    def __init__(self, manifest: FrozenContractManifest) -> None:
        self._manifest = manifest
        self._origin = _normalize_origin(manifest.origin)

    def authorize(self, request: ReadRequest) -> AuthorizedRequest:
        if type(request.operation) is not str or request.operation not in {
            *self._manifest.allowed_operations
        }:
            raise _denied()
        if type(request.method) is not str or request.method not in {"GET", "POST"}:
            raise _denied()
        if type(request.parameters_location) is not str:
            raise _denied()
        if not isinstance(request.parameters, Mapping):
            raise _denied()

        parsed = _parse_request_url(request.url)
        request_origin = _origin_from_split(parsed)
        if request_origin != self._origin:
            raise _denied()
        if parsed.query or parsed.fragment:
            raise _denied()
        _validate_request_path(parsed.path)

        parameters = _copy_strict_parameters(request.parameters)
        contract_request = self._manifest.find_request(request.operation, parameters)
        if contract_request is None:
            raise _denied()
        if (
            request.method != contract_request.method
            or parsed.path != contract_request.path
            or request.parameters_location != contract_request.parameters_location
        ):
            raise _denied()

        canonical_request = ReadRequest(
            operation=request.operation,
            method=request.method,
            url=request.url,
            parameters_location=request.parameters_location,
            parameters=MappingProxyType(parameters),
        )
        return AuthorizedRequest(
            request=canonical_request,
            contract_request=contract_request,
        )

    def authorize_redirect(
        self,
        request: ReadRequest | AuthorizedRequest,
        *,
        location: str,
    ) -> AuthorizedRequest:
        """Redirects are not part of the Loop 5 frozen contract."""
        del request, location
        raise _denied()


def _denied() -> RequestDeniedError:
    # Never echo a URL, parameter, token, or response into this safety error.
    return RequestDeniedError("request denied by the frozen read-only contract")


def _parse_request_url(value: object) -> SplitResult:
    if type(value) is not str or not value or value != value.strip():
        raise _denied()
    if "\\" in value or "\x00" in value or "?" in value or "#" in value:
        raise _denied()
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise _denied()
    try:
        parsed = urlsplit(value)
        # Accessing these properties forces urllib to reject malformed ports and
        # bracketed host forms before any comparison occurs.
        _ = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise _denied() from exc
    return parsed


def _normalize_origin(value: str) -> _NormalizedOrigin:
    parsed = _parse_request_url(value)
    if parsed.path or parsed.query or parsed.fragment:
        raise RequestDeniedError("manifest origin is not canonical")
    return _origin_from_split(parsed)


def _origin_from_split(parsed: SplitResult) -> _NormalizedOrigin:
    hostname = parsed.hostname
    if (
        parsed.scheme.casefold() != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or hostname.endswith(".")
        or parsed.netloc.endswith(":")
    ):
        raise _denied()
    try:
        explicit_port = parsed.port
    except ValueError as exc:
        raise _denied() from exc
    return _NormalizedOrigin(
        scheme="https",
        hostname=hostname.casefold(),
        effective_port=443 if explicit_port is None else explicit_port,
    )


def _validate_request_path(path: str) -> None:
    if (
        not path.startswith("/")
        or path == "/"
        or path.endswith("/")
        or "\\" in path
        or "%" in path
        or "//" in path
        or "\x00" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise _denied()


def _copy_strict_parameters(parameters: Mapping[str, object]) -> dict[str, object]:
    copied: dict[str, object] = {}
    for key, value in parameters.items():
        if type(key) is not str or not key or type(value) not in {str, int}:
            raise _denied()
        copied[key] = value
    if not copied:
        raise _denied()
    return copied
