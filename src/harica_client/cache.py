"""Cache JSON locale e opzionale dell'elenco certificati HARICA."""

from __future__ import annotations

import json
import math
import os
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import HaricaConfigurationError
from .i18n import tr

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
    """Restituisce il percorso XDG predefinito per la cache di un ambiente."""
    current = os.environ if environ is None else environ
    xdg_cache_home = current.get("XDG_CACHE_HOME", "").strip()
    if xdg_cache_home:
        root = Path(xdg_cache_home).expanduser()
        if not root.is_absolute():
            raise HaricaConfigurationError(tr("cache_absolute_xdg"))
    else:
        configured_home = current.get("HOME", "").strip()
        root = (Path(configured_home).expanduser() if configured_home else Path.home()) / ".cache"
        if not root.is_absolute():
            raise HaricaConfigurationError(tr("cache_absolute_home"))
    return _absolute_path(
        root / "harica-client" / "certificates" / f"{environment}.json"
    )


def resolve_cache_path(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Risolve il percorso secondo flag, variabile d'ambiente e default XDG."""
    current = os.environ if environ is None else environ
    if explicit_path is not None:
        return _absolute_path(explicit_path)
    configured = current.get(CACHE_FILE_ENV, "").strip()
    if CACHE_FILE_ENV in current:
        if not configured:
            raise HaricaConfigurationError(tr("env_empty", name=CACHE_FILE_ENV))
        return _absolute_path(configured)
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

    target = _absolute_path(path)
    _ensure_secure_directory(target.parent)
    if target.exists() or target.is_symlink():
        _validate_cache_file(target)

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
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = None
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, target)
        temporary_path = None
        os.chmod(target, 0o600)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
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
    target = _absolute_path(path)
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
    target = _absolute_path(path)
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
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise HaricaConfigurationError(tr("cache_changed_during_read", path=path))
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = None
            return stream.read()
    except HaricaConfigurationError:
        raise
    except (OSError, UnicodeError) as exc:
        raise HaricaConfigurationError(
            tr("cache_read_failed", path=path, error=exc)
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_cache_file(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise HaricaConfigurationError(tr("cache_missing", path=path)) from exc
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("cache_check_failed", path=path, error=exc)
        ) from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise HaricaConfigurationError(tr("cache_symlink", path=path))
    if not stat.S_ISREG(metadata.st_mode):
        raise HaricaConfigurationError(tr("cache_not_regular", path=path))
    if metadata.st_uid != os.geteuid():
        raise HaricaConfigurationError(tr("cache_wrong_owner", path=path))
    if metadata.st_mode & 0o077:
        raise HaricaConfigurationError(
            tr("cache_permissions", path=path, mode=stat.S_IMODE(metadata.st_mode))
        )
    if not metadata.st_mode & stat.S_IRUSR:
        raise HaricaConfigurationError(tr("cache_not_readable", path=path))
    _validate_secure_directory(path.parent)
    return metadata


def _ensure_secure_directory(path: Path) -> None:
    previous_umask = os.umask(0o077)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("cache_dir_create_failed", path=path, error=exc)
        ) from exc
    finally:
        os.umask(previous_umask)
    _validate_secure_directory(path)


def _validate_secure_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("cache_dir_check_failed", path=path, error=exc)
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise HaricaConfigurationError(tr("cache_dir_unsafe", path=path))
    if metadata.st_uid != os.geteuid():
        raise HaricaConfigurationError(tr("cache_dir_wrong_owner", path=path))
    if metadata.st_mode & 0o077:
        raise HaricaConfigurationError(
            tr("cache_dir_permissions", path=path, mode=stat.S_IMODE(metadata.st_mode))
        )


def _absolute_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))
