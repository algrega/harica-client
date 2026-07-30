"""Estrazione e salvataggio sicuro di un singolo certificato X.509 PEM."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import ssl
import stat
import tempfile
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .errors import HaricaConfigurationError
from .i18n import tr
from .platform_storage import IS_WINDOWS

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
_OID_LABELS = {
    "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.17": "postalCode",
}
_WINDOWS_RESERVED_STEMS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


@dataclass(frozen=True, slots=True)
class CertificateSummary:
    """Campi X.509 mostrati dopo un download riuscito."""

    serial_number: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    common_names: tuple[str, ...] = ()


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


def certificate_summary_from_pem(certificate_pem: str) -> CertificateSummary:
    """Estrae il riepilogo da un singolo PEM già normalizzato."""
    match = _PEM_CERTIFICATE.fullmatch(certificate_pem.strip())
    if match is None:
        raise HaricaConfigurationError(tr("download_certificate_invalid"))
    der = _decode_base64_der(match.group(1))
    return _parse_x509_der(der)


def automatic_download_destination(summary: CertificateSummary) -> Path:
    """Costruisce nella directory corrente un percorso sicuro da CN o seriale."""
    filename = automatic_download_filename(summary)
    try:
        directory = Path.cwd()
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("download_current_directory_failed", error=exc)
        ) from exc
    return _absolute_path(directory / filename)


def automatic_download_filename(summary: CertificateSummary) -> str:
    """Restituisce un nome PEM sicuro e deterministico."""
    common_name = _unique_common_name(summary.common_names)
    source = common_name or summary.serial_number
    stem = _safe_filename_stem(source, wildcard=common_name is not None)
    if not _contains_ascii_alphanumeric(stem):
        stem = _safe_filename_stem(summary.serial_number, wildcard=False)
    return f"{stem}.pem"


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
        if not IS_WINDOWS:
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

    _parse_x509_der(der)
    return f"{ssl.DER_cert_to_PEM_cert(der).strip()}\n"


def _decode_base64_der(value: str) -> bytes:
    compact = "".join(value.split())
    if not compact:
        raise HaricaConfigurationError(tr("download_certificate_empty"))
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HaricaConfigurationError(tr("download_certificate_invalid")) from exc


def _parse_x509_der(der: bytes) -> CertificateSummary:
    """Valida Certificate e restituisce i campi obbligatori del TBSCertificate."""
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
        serial_number = _format_serial_number(der[_start:_end])
        offset = next_field

        signature_tag, _start, _end, offset = _read_tlv(der, offset)
        issuer_tag, issuer_start, issuer_end, offset = _read_tlv(der, offset)
        validity_tag, validity_start, validity_end, offset = _read_tlv(der, offset)
        subject_tag, subject_start, subject_end, offset = _read_tlv(der, offset)
        public_key_tag, _start, _end, offset = _read_tlv(der, offset)
        if (
            signature_tag != 0x30
            or issuer_tag != 0x30
            or validity_tag != 0x30
            or subject_tag != 0x30
            or public_key_tag != 0x30
        ):
            raise ValueError
        if offset > tbs_end:
            raise ValueError

        issuer, _issuer_common_names = _parse_name_details(
            der,
            issuer_start,
            issuer_end,
        )
        subject, common_names = _parse_name_details(
            der,
            subject_start,
            subject_end,
        )
        not_before, not_after = _parse_validity(
            der,
            validity_start,
            validity_end,
        )

        # Delega a OpenSSL il parsing completo del certificato senza verificarne
        # attendibilità, stato o date: devono essere scaricabili anche revocati
        # e scaduti.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=der)
        return CertificateSummary(
            serial_number=serial_number,
            subject=subject,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            common_names=common_names,
        )
    except (IndexError, ValueError, ssl.SSLError) as exc:
        raise HaricaConfigurationError(tr("download_certificate_invalid")) from exc


def _format_serial_number(value: bytes) -> str:
    if not value:
        raise ValueError
    number = int.from_bytes(value, "big", signed=True)
    if number < 0:
        return f"-{-number:X}"
    if number == 0:
        return "00"
    return f"{number:X}"


def _parse_name(data: bytes, start: int, end: int) -> str:
    name, _common_names = _parse_name_details(data, start, end)
    return name


def _parse_name_details(
    data: bytes,
    start: int,
    end: int,
) -> tuple[str, tuple[str, ...]]:
    rdns: list[str] = []
    common_names: list[str] = []
    offset = start
    while offset < end:
        set_tag, set_start, set_end, offset = _read_tlv(data, offset)
        if set_tag != 0x31:
            raise ValueError
        attributes: list[str] = []
        attribute_offset = set_start
        while attribute_offset < set_end:
            sequence_tag, sequence_start, sequence_end, attribute_offset = _read_tlv(
                data,
                attribute_offset,
            )
            if sequence_tag != 0x30:
                raise ValueError
            oid_tag, oid_start, oid_end, value_offset = _read_tlv(
                data,
                sequence_start,
            )
            if oid_tag != 0x06:
                raise ValueError
            value_tag, value_start, value_end, value_offset = _read_tlv(
                data,
                value_offset,
            )
            if value_offset != sequence_end:
                raise ValueError
            oid = _decode_oid(data[oid_start:oid_end])
            label = _OID_LABELS.get(oid, oid)
            value = _decode_directory_string(
                value_tag,
                data[value_start:value_end],
            )
            if oid == "2.5.4.3":
                common_names.append(value)
            attributes.append(f"{label}={_escape_distinguished_name_value(value)}")
        if attribute_offset != set_end or not attributes:
            raise ValueError
        rdns.append("+".join(attributes))
    if offset != end:
        raise ValueError
    return ", ".join(rdns), tuple(common_names)


def _unique_common_name(values: Sequence[str]) -> str | None:
    unique: dict[str, str] = {}
    for value in values:
        normalized = unicodedata.normalize("NFKC", value).strip()
        if normalized:
            unique.setdefault(normalized, normalized)
    if len(unique) > 1:
        raise HaricaConfigurationError(tr("download_common_name_ambiguous"))
    return next(iter(unique.values()), None)


def _safe_filename_stem(value: str, *, wildcard: bool) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip()
    if wildcard and normalized.startswith("*."):
        normalized = f"wildcard.{normalized[2:]}"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", normalized)
    safe = safe.strip(".")
    if safe in {"", ".", ".."}:
        return ""
    if len(safe) > 200:
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
        prefix = safe[:187].rstrip(".")
        safe = f"{prefix}-{digest}"
    if safe.partition(".")[0].upper() in _WINDOWS_RESERVED_STEMS:
        safe = f"_{safe}"
    return safe


def _contains_ascii_alphanumeric(value: str) -> bool:
    return any(
        character.isascii() and character.isalnum()
        for character in value
    )


def _decode_oid(value: bytes) -> str:
    if not value:
        raise ValueError
    subidentifiers: list[int] = []
    current = 0
    continued = False
    for byte in value:
        if not continued and byte == 0x80:
            raise ValueError
        current = (current << 7) | (byte & 0x7F)
        continued = bool(byte & 0x80)
        if not continued:
            subidentifiers.append(current)
            current = 0
    if continued or not subidentifiers:
        raise ValueError
    first = subidentifiers[0]
    first_arc = min(first // 40, 2)
    arcs = [first_arc, first - (first_arc * 40), *subidentifiers[1:]]
    return ".".join(str(arc) for arc in arcs)


def _decode_directory_string(tag: int, value: bytes) -> str:
    encodings = {
        0x0C: "utf-8",
        0x12: "ascii",
        0x13: "ascii",
        0x14: "latin-1",
        0x16: "ascii",
        0x1A: "ascii",
        0x1B: "latin-1",
        0x1C: "utf-32-be",
        0x1E: "utf-16-be",
    }
    encoding = encodings.get(tag)
    if encoding is None:
        return f"#{value.hex().upper()}"
    return value.decode(encoding)


def _escape_distinguished_name_value(value: str) -> str:
    escaped: list[str] = []
    last_index = len(value) - 1
    for index, character in enumerate(value):
        if character in {",", "+", '"', "\\", "<", ">", ";", "="}:
            escaped.append(f"\\{character}")
        elif (index == 0 and character in {" ", "#"}) or (
            index == last_index and character == " "
        ):
            escaped.append(f"\\{character}")
        elif ord(character) < 0x20 or ord(character) == 0x7F:
            escaped.extend(f"\\{byte:02X}" for byte in character.encode("utf-8"))
        else:
            escaped.append(character)
    return "".join(escaped)


def _parse_validity(data: bytes, start: int, end: int) -> tuple[str, str]:
    first_tag, first_start, first_end, offset = _read_tlv(data, start)
    second_tag, second_start, second_end, offset = _read_tlv(data, offset)
    if offset != end:
        raise ValueError
    return (
        _parse_asn1_time(first_tag, data[first_start:first_end]),
        _parse_asn1_time(second_tag, data[second_start:second_end]),
    )


def _parse_asn1_time(tag: int, value: bytes) -> str:
    text = value.decode("ascii")
    if tag == 0x17:
        match = re.fullmatch(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})", text)
        if match is None:
            raise ValueError
        short_year, month, day, hour, minute, second, zone = match.groups()
        numeric_year = int(short_year)
        year = 1900 + numeric_year if numeric_year >= 50 else 2000 + numeric_year
        fraction = ""
    elif tag == 0x18:
        match = re.fullmatch(
            r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:[.,](\d+))?(Z|[+-]\d{4})",
            text,
        )
        if match is None:
            raise ValueError
        year, month, day, hour, minute, second, fraction, zone = match.groups()
        year = int(year)
    else:
        raise ValueError

    if zone == "Z":
        selected_timezone = timezone.utc
    else:
        sign = 1 if zone[0] == "+" else -1
        offset = timedelta(
            hours=int(zone[1:3]),
            minutes=int(zone[3:5]),
        )
        selected_timezone = timezone(sign * offset)
    microsecond = int(((fraction or "") + "000000")[:6])
    timestamp = datetime(
        year,
        int(month),
        int(day),
        int(hour),
        int(minute),
        int(second or 0),
        microsecond,
        tzinfo=selected_timezone,
    ).astimezone(timezone.utc)
    return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")


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
