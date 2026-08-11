from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass

CHENGFENG_CREDENTIAL_TARGET = "DaHeLogistics/Chengfeng/Primary"
_CRED_TYPE_GENERIC = 1


class CredentialUnavailableError(RuntimeError):
    """Raised when the fixed current-user credential cannot be read."""


@dataclass(frozen=True, slots=True)
class SavedCredential:
    username: str
    password: str


class _Credential(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", wintypes.LPVOID),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def read_saved_credential() -> SavedCredential:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    credential_pointer = ctypes.POINTER(_Credential)()
    advapi32.CredReadW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(_Credential)),
    ]
    advapi32.CredReadW.restype = wintypes.BOOL
    advapi32.CredFree.argtypes = [wintypes.LPVOID]
    advapi32.CredFree.restype = None
    if not advapi32.CredReadW(
        CHENGFENG_CREDENTIAL_TARGET,
        _CRED_TYPE_GENERIC,
        0,
        ctypes.byref(credential_pointer),
    ):
        raise CredentialUnavailableError("saved credential is unavailable")
    try:
        credential = credential_pointer.contents
        username = credential.UserName or ""
        blob_size = int(credential.CredentialBlobSize)
        if blob_size < 2 or blob_size % 2 != 0 or not username:
            raise CredentialUnavailableError("saved credential is invalid")
        password = ctypes.string_at(credential.CredentialBlob, blob_size).decode(
            "utf-16-le"
        )
        if not password:
            raise CredentialUnavailableError("saved credential is invalid")
        return SavedCredential(username=username, password=password)
    finally:
        advapi32.CredFree(credential_pointer)
