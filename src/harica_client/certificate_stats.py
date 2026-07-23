"""Statistiche calcolate esclusivamente sui certificati della cache locale."""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from .cache import CacheSnapshot, cache_age_hours

KNOWN_STATUSES = ("valid", "revoked", "expired")
_UTC = timezone.utc


@dataclass(frozen=True)
class NormalizedCertificate:
    """Vista normalizzata di un record HARICA."""

    index: int
    serial: str
    status: str
    valid_from: datetime | None
    valid_from_state: str
    valid_to: datetime | None
    valid_to_state: str
    revoked_at: datetime | None
    revoked_at_state: str
    is_revoked: bool | None
    is_revoked_state: str
    cn: str
    friendly_name: str
    user: str
    user_email: str


def _normalized_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _field(
    record: Mapping[str, Any],
    *names: str,
) -> tuple[Any, bool]:
    normalized = {_normalized_key(key): value for key, value in record.items()}
    for name in names:
        key = _normalized_key(name)
        if key in normalized:
            return normalized[key], True
    return None, False


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _parse_datetime(value: Any, found: bool) -> tuple[datetime | None, str]:
    if not found or value is None or (isinstance(value, str) and not value.strip()):
        return None, "missing"
    if not isinstance(value, str):
        return None, "invalid"

    candidate = value.strip()
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None, "invalid"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_UTC)
    try:
        return parsed.astimezone(_UTC), "valid"
    except (OverflowError, ValueError):
        return None, "invalid"


def _split_unescaped(value: str, separator: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    quoted = False

    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
            current.append(character)
        elif character == '"':
            quoted = not quoted
            current.append(character)
        elif character == separator and not quoted:
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))
    return parts


def _unescape_dn_value(value: str) -> str:
    candidate = value.strip()
    if len(candidate) >= 2 and candidate[0] == candidate[-1] == '"':
        candidate = candidate[1:-1]
    output: list[str] = []
    index = 0
    hexadecimal = frozenset("0123456789abcdefABCDEF")
    while index < len(candidate):
        if candidate[index] != "\\" or index + 1 >= len(candidate):
            output.append(candidate[index])
            index += 1
            continue
        if (
            index + 2 < len(candidate)
            and candidate[index + 1] in hexadecimal
            and candidate[index + 2] in hexadecimal
        ):
            encoded = bytearray()
            while (
                index + 2 < len(candidate)
                and candidate[index] == "\\"
                and candidate[index + 1] in hexadecimal
                and candidate[index + 2] in hexadecimal
            ):
                encoded.append(int(candidate[index + 1 : index + 3], 16))
                index += 3
            output.append(encoded.decode("utf-8", errors="replace"))
        else:
            output.append(candidate[index + 1])
            index += 2
    return "".join(output).strip()


def _common_name_from_dn(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    comma_components = _split_unescaped(value, ",")
    components = [
        component
        for comma_component in comma_components
        for component in _split_unescaped(comma_component, ";")
    ]
    for component in components:
        for attribute in _split_unescaped(component, "+"):
            pair = _split_unescaped(attribute, "=")
            if len(pair) < 2:
                continue
            name = pair[0].strip().casefold()
            if name in {"cn", "2.5.4.3", "oid.2.5.4.3"}:
                return _unescape_dn_value("=".join(pair[1:]))
    return ""


def normalize_certificate(
    record: Mapping[str, Any],
    *,
    index: int = 0,
) -> NormalizedCertificate:
    """Normalizza un certificato senza modificare il record originale."""

    serial, _ = _field(record, "serial", "serialNumber")
    status, _ = _field(record, "status")
    valid_from_raw, valid_from_found = _field(
        record, "validFrom", "notBefore", "valid_from"
    )
    valid_to_raw, valid_to_found = _field(record, "validTo", "notAfter", "valid_to")
    revoked_at_raw, revoked_at_found = _field(
        record, "revokedAt", "revocationDate", "revoked_at"
    )
    is_revoked_raw, is_revoked_found = _field(record, "isRevoked", "is_revoked")
    friendly_name, _ = _field(record, "friendlyName", "friendly_name")
    user, _ = _field(record, "user", "owner")
    user_email, _ = _field(record, "userEmail", "email", "user_email")

    explicit_cn, _ = _field(record, "CN", "commonName", "common_name")
    cn = _text(explicit_cn)
    if not cn:
        dn, _ = _field(record, "dN", "distinguishedName", "subject")
        cn = _common_name_from_dn(dn)

    valid_from, valid_from_state = _parse_datetime(
        valid_from_raw, valid_from_found
    )
    valid_to, valid_to_state = _parse_datetime(valid_to_raw, valid_to_found)
    revoked_at, revoked_at_state = _parse_datetime(
        revoked_at_raw, revoked_at_found
    )

    if not is_revoked_found or is_revoked_raw is None:
        is_revoked = None
        is_revoked_state = "missing"
    elif isinstance(is_revoked_raw, bool):
        is_revoked = is_revoked_raw
        is_revoked_state = "valid"
    else:
        is_revoked = None
        is_revoked_state = "invalid"

    return NormalizedCertificate(
        index=index,
        serial=_text(serial),
        status=_text(status).casefold(),
        valid_from=valid_from,
        valid_from_state=valid_from_state,
        valid_to=valid_to,
        valid_to_state=valid_to_state,
        revoked_at=revoked_at,
        revoked_at_state=revoked_at_state,
        is_revoked=is_revoked,
        is_revoked_state=is_revoked_state,
        cn=cn,
        friendly_name=_text(friendly_name),
        user=_text(user),
        user_email=_text(user_email),
    )


def normalize_certificates(
    records: Iterable[Mapping[str, Any]],
) -> list[NormalizedCertificate]:
    return [
        normalize_certificate(record, index=index)
        for index, record in enumerate(records)
    ]


def _utc_now(now: datetime | None) -> datetime:
    current = now or datetime.now(_UTC)
    if current.tzinfo is None:
        raise ValueError("now must include a timezone")
    return current.astimezone(_UTC)


def _format_utc(value: datetime) -> str:
    return value.astimezone(_UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _remaining_seconds(valid_to: datetime, now: datetime) -> float:
    return (valid_to - now).total_seconds()


def summary_report(
    snapshot: CacheSnapshot,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Crea il riepilogo generale della cache."""

    current = _utc_now(now)
    certificates = normalize_certificates(snapshot.certificates)
    statuses = Counter(certificate.status for certificate in certificates)
    unknown = sum(
        count for status, count in statuses.items() if status not in KNOWN_STATUSES
    )
    buckets = {
        "days0To7": 0,
        "days8To30": 0,
        "days31To60": 0,
        "days61To90": 0,
        "over90Days": 0,
    }

    for certificate in certificates:
        if certificate.status != "valid" or certificate.valid_to is None:
            continue
        remaining = _remaining_seconds(certificate.valid_to, current)
        if remaining < 0:
            continue
        if remaining <= 7 * 86400:
            buckets["days0To7"] += 1
        elif remaining <= 30 * 86400:
            buckets["days8To30"] += 1
        elif remaining <= 60 * 86400:
            buckets["days31To60"] += 1
        elif remaining <= 90 * 86400:
            buckets["days61To90"] += 1
        else:
            buckets["over90Days"] += 1

    revoked_since = current - timedelta(days=30)
    recent_revocations = sum(
        1
        for certificate in certificates
        if certificate.revoked_at is not None
        and revoked_since <= certificate.revoked_at <= current
    )

    return {
        "cache": {
            "createdAt": _format_utc(snapshot.created_at),
            "ageHours": round(cache_age_hours(snapshot, now=current), 2),
            "environment": snapshot.environment,
            "baseUrl": snapshot.base_url,
        },
        "total": len(certificates),
        "statusCounts": {
            "valid": statuses["valid"],
            "revoked": statuses["revoked"],
            "expired": statuses["expired"],
            "unknown": unknown,
        },
        "expiryBuckets": buckets,
        "revokedLast30Days": recent_revocations,
        "missingUser": sum(not certificate.user for certificate in certificates),
        "missingUserEmail": sum(
            not certificate.user_email for certificate in certificates
        ),
        "missingCN": sum(not certificate.cn for certificate in certificates),
        "invalidDates": sum(
            certificate.valid_from_state != "valid"
            or certificate.valid_to_state != "valid"
            or certificate.revoked_at_state == "invalid"
            for certificate in certificates
        ),
    }


def summary_rows(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Appiattisce il riepilogo nel formato metric/value usato dal CSV."""

    cache = report["cache"]
    status_counts = report["statusCounts"]
    expiry_buckets = report["expiryBuckets"]
    values = (
        ("cache.createdAt", cache["createdAt"]),
        ("cache.ageHours", cache["ageHours"]),
        ("cache.environment", cache["environment"]),
        ("cache.baseUrl", cache["baseUrl"]),
        ("total", report["total"]),
        ("status.valid", status_counts["valid"]),
        ("status.revoked", status_counts["revoked"]),
        ("status.expired", status_counts["expired"]),
        ("status.unknown", status_counts["unknown"]),
        ("expiry.days0To7", expiry_buckets["days0To7"]),
        ("expiry.days8To30", expiry_buckets["days8To30"]),
        ("expiry.days31To60", expiry_buckets["days31To60"]),
        ("expiry.days61To90", expiry_buckets["days61To90"]),
        ("expiry.over90Days", expiry_buckets["over90Days"]),
        ("revokedLast30Days", report["revokedLast30Days"]),
        ("missingUser", report["missingUser"]),
        ("missingUserEmail", report["missingUserEmail"]),
        ("missingCN", report["missingCN"]),
        ("invalidDates", report["invalidDates"]),
    )
    return [{"metric": metric, "value": value} for metric, value in values]


def expirations_report(
    records: Sequence[Mapping[str, Any]],
    *,
    within_days: int = 30,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Elenca i certificati validi in scadenza nell'intervallo richiesto."""

    if within_days <= 0:
        raise ValueError("within_days must be positive")
    current = _utc_now(now)
    normalized = normalize_certificates(records)
    rows: list[tuple[datetime, dict[str, Any]]] = []
    skipped = 0

    for certificate in normalized:
        if certificate.status != "valid":
            continue
        if certificate.valid_to is None:
            skipped += 1
            continue
        remaining = _remaining_seconds(certificate.valid_to, current)
        if remaining < 0 or remaining > within_days * 86400:
            continue
        rows.append(
            (
                certificate.valid_to,
                {
                    "serial": certificate.serial,
                    "CN": certificate.cn,
                    "friendlyName": certificate.friendly_name,
                    "userEmail": certificate.user_email,
                    "validTo": _format_utc(certificate.valid_to),
                    "daysRemaining": math.ceil(remaining / 86400),
                },
            )
        )

    rows.sort(
        key=lambda item: (
            item[0],
            item[1]["CN"].casefold(),
            item[1]["serial"].casefold(),
        )
    )
    return {
        "withinDays": within_days,
        "skippedInvalidDates": skipped,
        "certificates": [row for _, row in rows],
    }


def owners_report(
    records: Sequence[Mapping[str, Any]],
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Raggruppa i certificati per email del responsabile."""

    current = _utc_now(now)
    groups: dict[str, list[NormalizedCertificate]] = defaultdict(list)
    for certificate in normalize_certificates(records):
        groups[certificate.user_email.casefold()].append(certificate)

    rows: list[dict[str, Any]] = []
    for group in groups.values():
        representative_email = next(
            (certificate.user_email for certificate in group if certificate.user_email),
            "",
        )
        users = sorted(
            {certificate.user for certificate in group if certificate.user},
            key=str.casefold,
        )
        statuses = Counter(certificate.status for certificate in group)
        unknown = sum(
            count for status, count in statuses.items() if status not in KNOWN_STATUSES
        )
        expiring = sum(
            1
            for certificate in group
            if certificate.status == "valid"
            and certificate.valid_to is not None
            and 0 <= _remaining_seconds(certificate.valid_to, current) <= 30 * 86400
        )
        rows.append(
            {
                "userEmail": representative_email,
                "user": "; ".join(users),
                "total": len(group),
                "valid": statuses["valid"],
                "revoked": statuses["revoked"],
                "expired": statuses["expired"],
                "unknown": unknown,
                "expiringWithin30Days": expiring,
            }
        )

    rows.sort(key=lambda row: (-row["total"], row["userEmail"].casefold()))
    return rows


def quality_report(
    records: Sequence[Mapping[str, Any]],
) -> list[dict[str, str]]:
    """Restituisce una riga per certificato e anomalia rilevata."""

    certificates = normalize_certificates(records)
    serial_counts = Counter(
        certificate.serial.casefold()
        for certificate in certificates
        if certificate.serial
    )
    rows: list[dict[str, str]] = []

    def add_issue(certificate: NormalizedCertificate, issue: str) -> None:
        rows.append(
            {
                "serial": certificate.serial,
                "CN": certificate.cn,
                "friendlyName": certificate.friendly_name,
                "issue": issue,
            }
        )

    for certificate in certificates:
        if not certificate.serial:
            add_issue(certificate, "missing_serial")
        elif serial_counts[certificate.serial.casefold()] > 1:
            add_issue(certificate, "duplicate_serial")

        if certificate.valid_from_state == "missing":
            add_issue(certificate, "missing_valid_from")
        elif certificate.valid_from_state == "invalid":
            add_issue(certificate, "invalid_valid_from")
        if certificate.valid_to_state == "missing":
            add_issue(certificate, "missing_valid_to")
        elif certificate.valid_to_state == "invalid":
            add_issue(certificate, "invalid_valid_to")
        if (
            certificate.valid_from is not None
            and certificate.valid_to is not None
            and certificate.valid_to <= certificate.valid_from
        ):
            add_issue(certificate, "invalid_validity_range")

        if certificate.is_revoked_state == "missing":
            add_issue(certificate, "missing_is_revoked")
        elif certificate.is_revoked_state == "invalid":
            add_issue(certificate, "invalid_is_revoked")
        elif (certificate.status == "revoked") != certificate.is_revoked:
            add_issue(certificate, "revocation_status_mismatch")

        if certificate.revoked_at_state == "invalid":
            add_issue(certificate, "invalid_revoked_at")
        elif (
            certificate.revoked_at is None
            and (certificate.status == "revoked" or certificate.is_revoked is True)
        ):
            add_issue(certificate, "missing_revoked_at")
        elif certificate.revoked_at is not None and certificate.status != "revoked":
            add_issue(certificate, "unexpected_revoked_at")

        if not certificate.status:
            add_issue(certificate, "missing_status")
        elif certificate.status not in KNOWN_STATUSES:
            add_issue(certificate, "unknown_status")
        if not certificate.cn:
            add_issue(certificate, "missing_cn")
        if not certificate.user:
            add_issue(certificate, "missing_user")
        if not certificate.user_email:
            add_issue(certificate, "missing_user_email")
        if not certificate.friendly_name:
            add_issue(certificate, "missing_friendly_name")

    rows.sort(
        key=lambda row: (
            row["issue"],
            row["serial"].casefold(),
            row["CN"].casefold(),
        )
    )
    return rows
