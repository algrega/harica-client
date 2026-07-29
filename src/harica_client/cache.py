"""Cache JSON locale e opzionale dell'elenco certificati HARICA."""

from __future__ import annotations

import json
import math
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import HaricaConfigurationError
from .i18n import tr
from .platform_storage import (
    IS_WINDOWS,
    StoragePathError,
    atomic_write_bytes,
    cache_root,
    ensure_private_directory,
    read_stable_bytes,
    storage_path,
    validate_private_directory,
    validate_private_file,
)
from .windows_dpapi import DpapiError, protect, unprotect

CACHE_FILE_ENV = "HARICA_CLIENT_CACHE_FILE"
CACHE_SCHEMA_VERSION = 1
CACHE_STATUSES = ("valid", "revoked", "expired")


@dataclass(frozen=True, slots=True)
class CacheSnapshot:
    """Contenuto validato di una cache locale."""

    schema_version: int
    created_at: datetime
    environment: str
    base_url: str
    statuses: tuple[str, ...]
    certificates: list[dict[str, Any]]


def default_cache_path(
    environment: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Restituisce il percorso cache predefinito nativo della piattaforma."""
    current = os.environ if environ is None else environ
    try:
        root = cache_root(current)
    except StoragePathError as exc:
        keys = {
            "cache_root_not_absolute": (
                "windows_cache_absolute" if IS_WINDOWS else "cache_absolute_xdg"
            ),
            "home_not_absolute": "cache_absolute_home",
        }
        raise HaricaConfigurationError(
            tr(keys.get(exc.reason, "windows_cache_absolute"))
        ) from exc
    suffix = ".json.dpapi" if IS_WINDOWS else ".json"
    return root / "harica-client" / "certificates" / f"{environment}{suffix}"


def resolve_cache_path(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Risolve il percorso secondo flag, variabile d'ambiente e default."""
    current = os.environ if environ is None else environ
    if explicit_path is not None:
        return _validated_storage_path(explicit_path)
    configured = current.get(CACHE_FILE_ENV, "").strip()
    if CACHE_FILE_ENV in current:
        if not configured:
            raise HaricaConfigurationError(tr("env_empty", name=CACHE_FILE_ENV))
        return _validated_storage_path(configured)
    return default_cache_path(environment, environ=current)


def write_cache(
    path: Path | str,
    *,
    environment: str,
    base_url: str,
    certificates: Sequence[Mapping[str, Any]],
    now: datetime | None = None,
) -> CacheSnapshot:
    """Valida e salva una fotografia completa con sostituzione atomica."""
    created_at = _utc_now(now)
    rows = [dict(row) for row in certificates]
    snapshot = CacheSnapshot(
        schema_version=CACHE_SCHEMA_VERSION,
        created_at=created_at,
        environment=environment,
        base_url=base_url,
        statuses=CACHE_STATUSES,
        certificates=rows,
    )
    payload = {
        "schemaVersion": snapshot.schema_version,
        "createdAt": _format_timestamp(snapshot.created_at),
        "environment": snapshot.environment,
        "baseUrl": snapshot.base_url,
        "statuses": list(snapshot.statuses),
        "certificates": snapshot.certificates,
    }
    try:
        serialized = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    except (TypeError, ValueError) as exc:
        raise HaricaConfigurationError(tr("cache_not_serializable", error=exc)) from exc

    target = _validated_storage_path(path)
    _ensure_secure_directory(target.parent)
    if target.exists() or target.is_symlink():
        _validate_cache_file(target)

    try:
        content = serialized.encode("utf-8")
        if IS_WINDOWS:
            content = protect(content, purpose="cache")
        atomic_write_bytes(target, content)
    except DpapiError as exc:
        raise HaricaConfigurationError(
            tr("dpapi_protect_failed", path=target, error=exc)
        ) from exc
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("cache_write_failed", path=target, error=exc)
        ) from exc

    return snapshot


def read_cache(
    path: Path | str,
    *,
    expected_environment: str,
    max_age_hours: float | None = None,
    now: datetime | None = None,
) -> CacheSnapshot:
    """Legge e valida contenuto, sicurezza, ambiente ed eventuale età massima."""
    target = _validated_storage_path(path)
    content = _read_secure_text(target)
    if not content.strip():
        raise HaricaConfigurationError(tr("cache_empty", path=target))
    try:
        payload = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HaricaConfigurationError(tr("cache_invalid_json", path=target)) from exc

    snapshot = _snapshot_from_payload(payload, path=target)
    if snapshot.environment != expected_environment:
        raise HaricaConfigurationError(
            tr(
                "cache_environment_mismatch",
                actual=snapshot.environment,
                expected=expected_environment,
            )
        )

    current = _utc_now(now)
    age_seconds = (current - snapshot.created_at).total_seconds()
    if age_seconds < 0:
        raise HaricaConfigurationError(tr("cache_timestamp_future", path=target))
    if max_age_hours is not None:
        if not math.isfinite(max_age_hours) or max_age_hours <= 0:
            raise HaricaConfigurationError(tr("cache_max_age_positive"))
        if age_seconds > max_age_hours * 3600:
            raise HaricaConfigurationError(
                tr(
                    "cache_too_old",
                    age_hours=age_seconds / 3600,
                    max_age_hours=max_age_hours,
                )
            )
    return snapshot


def delete_cache(path: Path | str) -> Path:
    """Elimina esclusivamente un file cache valido e sicuro."""
    target = _validated_storage_path(path)
    _validate_cache_file(target)
    try:
        target.unlink()
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("cache_delete_failed", path=target, error=exc)
        ) from exc
    return target


def cache_age_hours(snapshot: CacheSnapshot, *, now: datetime | None = None) -> float:
    """Calcola l'età non negativa della fotografia in ore."""
    age = (_utc_now(now) - snapshot.created_at).total_seconds() / 3600
    return max(0.0, age)


def _snapshot_from_payload(payload: Any, *, path: Path) -> CacheSnapshot:
    if not isinstance(payload, dict):
        raise HaricaConfigurationError(tr("cache_invalid_structure", path=path))

    schema_version = payload.get("schemaVersion")
    if type(schema_version) is not int or schema_version != CACHE_SCHEMA_VERSION:
        raise HaricaConfigurationError(
            tr(
                "cache_schema_unsupported",
                actual=schema_version,
                expected=CACHE_SCHEMA_VERSION,
            )
        )
    created_at = _parse_timestamp(payload.get("createdAt"), path=path)
    environment = payload.get("environment")
    base_url = payload.get("baseUrl")
    statuses = payload.get("statuses")
    certificates = payload.get("certificates")
    if not isinstance(environment, str) or not environment.strip():
        raise HaricaConfigurationError(tr("cache_invalid_structure", path=path))
    if not isinstance(base_url, str) or not base_url.strip():
        raise HaricaConfigurationError(tr("cache_invalid_structure", path=path))
    if not isinstance(statuses, list) or tuple(statuses) != CACHE_STATUSES:
        raise HaricaConfigurationError(tr("cache_incomplete_statuses", path=path))
    if not isinstance(certificates, list) or not all(
        isinstance(row, dict) for row in certificates
    ):
        raise HaricaConfigurationError(tr("cache_invalid_structure", path=path))

    return CacheSnapshot(
        schema_version=schema_version,
        created_at=created_at,
        environment=environment,
        base_url=base_url,
        statuses=tuple(statuses),
        certificates=certificates,
    )


def _parse_timestamp(value: Any, *, path: Path) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HaricaConfigurationError(tr("cache_invalid_timestamp", path=path))
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as exc:
        raise HaricaConfigurationError(tr("cache_invalid_timestamp", path=path)) from exc
    if parsed.tzinfo is None:
        raise HaricaConfigurationError(tr("cache_invalid_timestamp", path=path))
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_now(value: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if value is None else value
    if current.tzinfo is None:
        raise HaricaConfigurationError(tr("cache_datetime_timezone"))
    return current.astimezone(timezone.utc)


def _read_secure_text(path: Path) -> str:
    metadata = _validate_cache_file(path)
    try:
        content = read_stable_bytes(path, metadata)
        if IS_WINDOWS:
            content = unprotect(content, purpose="cache")
        return content.decode("utf-8")
    except StoragePathError as exc:
        raise HaricaConfigurationError(
            tr("cache_changed_during_read", path=path)
        ) from exc
    except DpapiError as exc:
        key = (
            "dpapi_cache_invalid_format"
            if exc.reason == "invalid_format"
            else "dpapi_unprotect_failed"
        )
        values = {"path": exc.path}
        if key == "dpapi_unprotect_failed":
            values["error"] = exc
        raise HaricaConfigurationError(tr(key, **values)) from exc
    except (OSError, UnicodeError) as exc:
        raise HaricaConfigurationError(
            tr("cache_read_failed", path=path, error=exc)
        ) from exc


def _validate_cache_file(path: Path) -> os.stat_result:
    try:
        metadata = validate_private_file(path)
        validate_private_directory(path.parent)
        return metadata
    except FileNotFoundError as exc:
        raise HaricaConfigurationError(tr("cache_missing", path=path)) from exc
    except StoragePathError as exc:
        keys = {
            "reparse": "cache_reparse",
            "not_regular": "cache_not_regular",
            "wrong_owner": "cache_wrong_owner",
            "permissions": "cache_permissions",
            "not_readable": "cache_not_readable",
            "unsafe_directory": "cache_dir_unsafe",
        }
        key = keys.get(exc.reason, "cache_check_failed")
        values = {"path": exc.path}
        if exc.mode is not None:
            values["mode"] = exc.mode
        if key == "cache_check_failed":
            values["error"] = exc.reason
        raise HaricaConfigurationError(tr(key, **values)) from exc
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("cache_check_failed", path=path, error=exc)
        ) from exc


def _ensure_secure_directory(path: Path) -> None:
    try:
        ensure_private_directory(path)
    except StoragePathError as exc:
        keys = {
            "unsafe_directory": "cache_dir_unsafe",
            "wrong_owner": "cache_dir_wrong_owner",
            "permissions": "cache_dir_permissions",
        }
        key = keys.get(exc.reason, "cache_dir_check_failed")
        values = {"path": path}
        if exc.mode is not None:
            values["mode"] = exc.mode
        if key == "cache_dir_check_failed":
            values["error"] = exc.reason
        raise HaricaConfigurationError(tr(key, **values)) from exc
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("cache_dir_create_failed", path=path, error=exc)
        ) from exc


def _validated_storage_path(path: Path | str) -> Path:
    try:
        return storage_path(path)
    except StoragePathError as exc:
        keys = {
            "windows_path_not_absolute": "windows_path_not_absolute",
            "windows_path_not_local": "windows_path_not_local",
            "reparse": "cache_reparse",
        }
        key = keys.get(exc.reason, "windows_path_not_local")
        raise HaricaConfigurationError(tr(key, path=exc.path)) from exc
