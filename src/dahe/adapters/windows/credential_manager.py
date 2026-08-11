from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from typing import Protocol

from dahe.ports.platform_credentials import (
    CredentialNotFoundError,
    PlatformCredentialError,
    StoredPlatformCredential,
)

__all__ = [
    "CredentialNotFoundError",
    "StoredPlatformCredential",
    "WindowsCredentialVault",
]

CHENGFENG_CREDENTIAL_TARGET = "DaHeLogistics/Chengfeng/Primary"
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168
_MAX_USERNAME_LENGTH = 512
_MAX_PASSWORD_LENGTH = 512


class _CredentialBackend(Protocol):
    def read(self, target_name: str) -> StoredPlatformCredential: ...

    def write(
        self,
        target_name: str,
        credential: StoredPlatformCredential,
    ) -> None: ...

    def delete(self, target_name: str) -> bool: ...


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", _FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


class _CtypesCredentialBackend:
    def __init__(self) -> None:
        if os.name != "nt":
            raise PlatformCredentialError(
                "Windows Credential Manager is unavailable on this platform"
            )
        self._advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        self._cred_write = self._advapi32.CredWriteW
        self._cred_write.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
        self._cred_write.restype = wintypes.BOOL
        self._cred_read = self._advapi32.CredReadW
        self._cred_read.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(_CREDENTIALW)),
        ]
        self._cred_read.restype = wintypes.BOOL
        self._cred_delete = self._advapi32.CredDeleteW
        self._cred_delete.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        self._cred_delete.restype = wintypes.BOOL
        self._cred_free = self._advapi32.CredFree
        self._cred_free.argtypes = [ctypes.c_void_p]
        self._cred_free.restype = None

    def read(self, target_name: str) -> StoredPlatformCredential:
        pointer = ctypes.POINTER(_CREDENTIALW)()
        if not self._cred_read(
            target_name,
            _CRED_TYPE_GENERIC,
            0,
            ctypes.byref(pointer),
        ):
            error = ctypes.get_last_error()
            if error == _ERROR_NOT_FOUND:
                raise CredentialNotFoundError("credential is not configured")
            raise PlatformCredentialError(
                f"Windows credential read failed with error {error}"
            )
        password_buffer = bytearray()
        try:
            record = pointer.contents
            if record.CredentialBlobSize:
                password_buffer.extend(
                    ctypes.string_at(
                        record.CredentialBlob,
                        int(record.CredentialBlobSize),
                    )
                )
            try:
                password = password_buffer.decode("utf-16-le")
            except UnicodeDecodeError as exc:
                raise PlatformCredentialError(
                    "stored Windows credential is not valid UTF-16"
                ) from exc
            username = record.UserName or ""
            if not username or not password:
                raise PlatformCredentialError(
                    "stored Windows credential is incomplete"
                )
            return StoredPlatformCredential(username=username, password=password)
        finally:
            for index in range(len(password_buffer)):
                password_buffer[index] = 0
            self._cred_free(pointer)

    def write(
        self,
        target_name: str,
        credential: StoredPlatformCredential,
    ) -> None:
        blob = credential.password.encode("utf-16-le")
        buffer = ctypes.create_string_buffer(blob, len(blob))
        try:
            record = _CREDENTIALW()
            record.Type = _CRED_TYPE_GENERIC
            record.TargetName = target_name
            record.CredentialBlobSize = len(blob)
            record.CredentialBlob = ctypes.cast(
                buffer,
                ctypes.POINTER(ctypes.c_ubyte),
            )
            record.Persist = _CRED_PERSIST_LOCAL_MACHINE
            record.UserName = credential.username
            if not self._cred_write(ctypes.byref(record), 0):
                error = ctypes.get_last_error()
                raise PlatformCredentialError(
                    f"Windows credential write failed with error {error}"
                )
        finally:
            ctypes.memset(buffer, 0, len(blob))

    def delete(self, target_name: str) -> bool:
        if self._cred_delete(target_name, _CRED_TYPE_GENERIC, 0):
            return True
        error = ctypes.get_last_error()
        if error == _ERROR_NOT_FOUND:
            return False
        raise PlatformCredentialError(
            f"Windows credential delete failed with error {error}"
        )


class WindowsCredentialVault:
    """Store the fixed Chengfeng credential for the current Windows user."""

    def __init__(self, *, backend: _CredentialBackend | None = None) -> None:
        self._backend = backend or _CtypesCredentialBackend()

    def read(self) -> StoredPlatformCredential:
        return self._backend.read(CHENGFENG_CREDENTIAL_TARGET)

    def write(self, *, username: str, password: str) -> None:
        if (
            not username
            or username != username.strip()
            or "\x00" in username
            or len(username) > _MAX_USERNAME_LENGTH
        ):
            raise ValueError("username is invalid")
        if (
            not password
            or "\x00" in password
            or len(password) > _MAX_PASSWORD_LENGTH
        ):
            raise ValueError("password is invalid")
        self._backend.write(
            CHENGFENG_CREDENTIAL_TARGET,
            StoredPlatformCredential(username=username, password=password),
        )

    def delete(self) -> bool:
        return self._backend.delete(CHENGFENG_CREDENTIAL_TARGET)
