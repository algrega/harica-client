"""Estrazione e salvataggio sicuro di un singolo certificato X.509 PEM."""

from __future__ import annotations

import base64
import binascii
import os
import re
import ssl
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .errors import HaricaConfigurationError
from .i18n import tr

_PEM_CERTIFICATE = re.compile(
    r"\A-----BEGIN CERTIFICATE-----\s*"
    r"([A-Za-z0-9+/=\s]+?)"
    r"\s*-----END CERTIFICATE-----\Z"
)
_PRIVATE_KEY_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
)
_UNSUPPORTED_PEM_MARKERS = (
    "-----BEGIN PKCS7-----",
    "-----BEGIN PKCS #7-----",
    "-----BEGIN CMS-----",
    "-----BEGIN PKCS12-----",
)


def extract_certificate_pem(response: Any) -> str:
    """Estrae un solo certificato univoco e lo normalizza in formato PEM."""
    candidates: list[Any] = []
    _collect_certificate_values(response, candidates)
    if not candidates:
        raise HaricaConfigurationError(tr("download_certificate_missing"))

    normalized: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, str):
            raise HaricaConfigurationError(tr("download_certificate_not_text"))
        if not candidate.strip():
            raise HaricaConfigurationError(tr("download_certificate_empty"))
        normalized.add(_normalize_certificate(candidate))

    if len(normalized) != 1:
        raise HaricaConfigurationError(tr("download_certificate_ambiguous"))
    return normalized.pop()


def validate_download_destination(
    path: Path | str,
    *,
    force: bool = False,
) -> Path:
    """Controlla la destinazione senza creare o modificare file."""
    target = _absolute_path(path)
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return target
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("download_destination_check_failed", path=target, error=exc)
        ) from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise HaricaConfigurationError(tr("download_destination_symlink", path=target))
    if not stat.S_ISREG(metadata.st_mode):
        raise HaricaConfigurationError(
            tr("download_destination_not_regular", path=target)
        )
    if not force:
        raise HaricaConfigurationError(tr("download_destination_exists", path=target))
    return target


def write_certificate_pem(
    path: Path | str,
    certificate_pem: str,
    *,
    force: bool = False,
) -> Path:
    """Scrive atomicamente il PEM con permessi 0644."""
    target = validate_download_destination(path, force=force)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("download_directory_create_failed", path=target.parent, error=exc)
        ) from exc
    if not target.parent.is_dir():
        raise HaricaConfigurationError(
            tr("download_directory_not_directory", path=target.parent)
        )

    # Ripete il controllo dopo la creazione della directory e subito prima
    # della scrittura per ridurre la finestra di race sulla destinazione.
    validate_download_destination(target, force=force)

    descriptor: int | None = None
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            text=True,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            descriptor = None
            stream.write(certificate_pem)
            stream.flush()
            os.fsync(stream.fileno())

        validate_download_destination(target, force=force)
        os.replace(temporary_path, target)
        temporary_path = None
    except HaricaConfigurationError:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    except (OSError, UnicodeError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise HaricaConfigurationError(
            tr("download_write_failed", path=target, error=exc)
        ) from exc

    return target


def _collect_certificate_values(value: Any, candidates: list[Any]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.casefold() == "certificate":
                candidates.append(item)
            else:
                _collect_certificate_values(item, candidates)
        return
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for item in value:
            _collect_certificate_values(item, candidates)


def _normalize_certificate(value: str) -> str:
    text = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    upper = text.upper()
    if any(marker in upper for marker in _PRIVATE_KEY_MARKERS):
        raise HaricaConfigurationError(tr("download_private_key_rejected"))
    if any(marker in upper for marker in _UNSUPPORTED_PEM_MARKERS):
        raise HaricaConfigurationError(tr("download_format_unsupported"))
    if upper.count("-----BEGIN CERTIFICATE-----") != 1 or upper.count(
        "-----END CERTIFICATE-----"
    ) != 1:
        if "-----BEGIN CERTIFICATE-----" in upper:
            raise HaricaConfigurationError(tr("download_multiple_certificates"))
        if "-----BEGIN " in upper:
            raise HaricaConfigurationError(tr("download_format_unsupported"))
        der = _decode_base64_der(text)
    else:
        match = _PEM_CERTIFICATE.fullmatch(text)
        if match is None:
            raise HaricaConfigurationError(tr("download_certificate_invalid"))
        der = _decode_base64_der(match.group(1))

    _validate_x509_der(der)
    return f"{ssl.DER_cert_to_PEM_cert(der).strip()}\n"


def _decode_base64_der(value: str) -> bytes:
    compact = "".join(value.split())
    if not compact:
        raise HaricaConfigurationError(tr("download_certificate_empty"))
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HaricaConfigurationError(tr("download_certificate_invalid")) from exc


def _validate_x509_der(der: bytes) -> None:
    """Valida la struttura ASN.1 esterna e i campi obbligatori di Certificate."""
    try:
        root_tag, root_start, root_end, next_offset = _read_tlv(der, 0)
        if root_tag != 0x30 or next_offset != len(der):
            raise ValueError

        tbs_tag, tbs_start, tbs_end, offset = _read_tlv(der, root_start)
        algorithm_tag, algorithm_start, algorithm_end, offset = _read_tlv(der, offset)
        signature_tag, signature_start, signature_end, offset = _read_tlv(der, offset)
        if (
            tbs_tag != 0x30
            or algorithm_tag != 0x30
            or signature_tag != 0x03
            or offset != root_end
            or algorithm_start == algorithm_end
            or signature_end - signature_start < 2
            or der[signature_start] > 7
        ):
            raise ValueError

        offset = tbs_start
        first_tag, _start, _end, next_field = _read_tlv(der, offset)
        if first_tag == 0xA0:
            offset = next_field
            first_tag, _start, _end, next_field = _read_tlv(der, offset)
        if first_tag != 0x02:
            raise ValueError
        offset = next_field

        # signature, issuer, validity, subject e subjectPublicKeyInfo.
        for expected_tag in (0x30, 0x30, 0x30, 0x30, 0x30):
            actual_tag, _start, _end, offset = _read_tlv(der, offset)
            if actual_tag != expected_tag:
                raise ValueError
        if offset > tbs_end:
            raise ValueError

        # Delega a OpenSSL il parsing completo del certificato senza verificarne
        # attendibilità, stato o date: devono essere scaricabili anche revocati
        # e scaduti.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=der)
    except (IndexError, ValueError, ssl.SSLError) as exc:
        raise HaricaConfigurationError(tr("download_certificate_invalid")) from exc


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    if offset + 2 > len(data):
        raise ValueError
    tag = data[offset]
    first_length = data[offset + 1]
    cursor = offset + 2
    if first_length & 0x80:
        length_octets = first_length & 0x7F
        if length_octets == 0 or length_octets > 4 or cursor + length_octets > len(data):
            raise ValueError
        if data[cursor] == 0:
            raise ValueError
        length = int.from_bytes(data[cursor : cursor + length_octets], "big")
        if length < 128:
            raise ValueError
        cursor += length_octets
    else:
        length = first_length
    end = cursor + length
    if end > len(data):
        raise ValueError
    return tag, cursor, end, end


def _absolute_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))
