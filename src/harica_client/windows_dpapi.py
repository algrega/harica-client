"""Protezione DPAPI per i dati locali di harica-client su Windows."""

from __future__ import annotations

import base64
import binascii
import ctypes
import os
from dataclasses import dataclass


_HEADER = b"HARICA-CLIENT-DPAPI/1 "
_PURPOSES = frozenset({"api-key", "cache"})
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


@dataclass(frozen=True, slots=True)
class DpapiError(Exception):
    """Errore DPAPI classificato senza includere il contenuto protetto."""

    reason: str
    winerror: int | None = None

    def __str__(self) -> str:
        if self.winerror is None:
            return self.reason
        return f"{self.reason} (Windows error {self.winerror})"


if os.name == "nt":

    class _DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]


    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_wchar_p,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptProtectData.restype = ctypes.c_int
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptUnprotectData.restype = ctypes.c_int
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p


def protect(payload: bytes, *, purpose: str) -> bytes:
    """Cifra e autentica un payload per l'utente Windows corrente."""
    _validate_purpose(purpose)
    if os.name != "nt":
        raise DpapiError("unavailable")
    encrypted = _crypt(payload, purpose=purpose, decrypt=False)
    return _encode_envelope(encrypted, purpose=purpose)


def unprotect(envelope: bytes, *, purpose: str) -> bytes:
    """Valida l'envelope e decifra il payload per l'utente corrente."""
    _validate_purpose(purpose)
    encrypted = _decode_envelope(envelope, purpose=purpose)
    if os.name != "nt":
        raise DpapiError("unavailable")
    return _crypt(encrypted, purpose=purpose, decrypt=True)


def _validate_purpose(purpose: str) -> None:
    if purpose not in _PURPOSES:
        raise ValueError(f"unsupported DPAPI purpose: {purpose}")


def _encode_envelope(encrypted: bytes, *, purpose: str) -> bytes:
    encoded = base64.b64encode(encrypted)
    return _HEADER + purpose.encode("ascii") + b"\n" + encoded + b"\n"


def _decode_envelope(envelope: bytes, *, purpose: str) -> bytes:
    expected = _HEADER + purpose.encode("ascii")
    lines = envelope.splitlines()
    if len(lines) != 2 or lines[0] != expected or not lines[1]:
        raise DpapiError("invalid_format")
    try:
        return base64.b64decode(lines[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DpapiError("invalid_format") from exc


def _crypt(payload: bytes, *, purpose: str, decrypt: bool) -> bytes:
    if not payload:
        raise DpapiError("invalid_format")
    input_blob, input_buffer = _make_blob(payload)
    entropy_blob, entropy_buffer = _make_blob(
        f"harica-client/{purpose}/v1".encode("ascii")
    )
    output_blob = _DataBlob()
    function = (
        _crypt32.CryptUnprotectData if decrypt else _crypt32.CryptProtectData
    )
    if decrypt:
        succeeded = function(
            ctypes.byref(input_blob),
            None,
            ctypes.byref(entropy_blob),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
    else:
        succeeded = function(
            ctypes.byref(input_blob),
            "harica-client",
            ctypes.byref(entropy_blob),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
    if not succeeded:
        reason = "unprotect_failed" if decrypt else "protect_failed"
        raise DpapiError(reason, ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        # I buffer di input devono restare vivi fino al termine della chiamata nativa.
        del input_buffer, entropy_buffer
        _kernel32.LocalFree(ctypes.cast(output_blob.pbData, ctypes.c_void_p))


def _make_blob(payload: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(payload, len(payload))
    blob = _DataBlob(
        len(payload),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buffer
