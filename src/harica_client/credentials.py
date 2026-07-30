"""Gestione multipiattaforma delle credenziali HARICA."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .errors import HaricaConfigurationError
from .i18n import tr
from .platform_storage import (
    IS_WINDOWS,
    StoragePathError,
    atomic_write_bytes,
    config_root,
    ensure_private_directory,
    read_stable_bytes,
    storage_path,
    validate_private_directory,
    validate_private_file,
)
from .windows_dpapi import DpapiError, protect, unprotect

API_KEY_ENV = "HARICA_API_KEY"
API_KEY_FILE_ENV = "HARICA_API_KEY_FILE"


@dataclass(frozen=True, slots=True)
class CredentialLocation:
    """Origine selezionata secondo la precedenza documentata."""

    source: str
    path: Path | None = None
    direct_value: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    """API key risolta e relativa origine, per uso interno alla CLI."""

    api_key: str = field(repr=False)
    source: str
    path: Path | None = None


@dataclass(frozen=True, slots=True)
class CredentialStatus:
    """Stato ispezionabile senza esporre il segreto."""

    valid: bool
    source: str
    path: Path | None
    detail: str


def default_api_key_path(
    environment: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Restituisce il percorso predefinito nativo della piattaforma."""
    current = os.environ if environ is None else environ
    try:
        root = config_root(current)
    except StoragePathError as exc:
        raise _root_configuration_error(exc) from exc
    suffix = ".key.dpapi" if IS_WINDOWS else ".key"
    return root / "harica-client" / "credentials" / f"{environment}{suffix}"


def select_credential_location(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> CredentialLocation:
    """Seleziona la sorgente senza leggere né mostrare il segreto."""
    current = os.environ if environ is None else environ
    if explicit_path is not None:
        return CredentialLocation(
            source="--api-key-file",
            path=_validated_storage_path(explicit_path),
        )
    if API_KEY_ENV in current:
        return CredentialLocation(source=API_KEY_ENV, direct_value=current[API_KEY_ENV])
    if API_KEY_FILE_ENV in current:
        configured = current[API_KEY_FILE_ENV].strip()
        if not configured:
            raise HaricaConfigurationError(tr("env_empty", name=API_KEY_FILE_ENV))
        return CredentialLocation(
            source=API_KEY_FILE_ENV,
            path=_validated_storage_path(configured),
        )
    preferred = default_api_key_path(environment, environ=current)
    return CredentialLocation(source=tr("default_file"), path=preferred)


def credential_destination(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Seleziona la destinazione per set/delete, ignorando HARICA_API_KEY."""
    current = os.environ if environ is None else environ
    if explicit_path is not None:
        return _validated_storage_path(explicit_path)
    if API_KEY_FILE_ENV in current:
        configured = current[API_KEY_FILE_ENV].strip()
        if not configured:
            raise HaricaConfigurationError(tr("env_empty", name=API_KEY_FILE_ENV))
        return _validated_storage_path(configured)
    return default_api_key_path(environment, environ=current)


def credential_deletion_target(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Seleziona il file di credenziali da eliminare."""
    current = os.environ if environ is None else environ
    if explicit_path is not None or API_KEY_FILE_ENV in current:
        return credential_destination(
            environment,
            explicit_path=explicit_path,
            environ=current,
        )
    return default_api_key_path(environment, environ=current)


def resolve_api_key(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> ResolvedCredential:
    """Risolve e valida l'API key secondo la precedenza della CLI."""
    location = select_credential_location(
        environment,
        explicit_path=explicit_path,
        environ=environ,
    )
    if location.path is None:
        api_key = (location.direct_value or "").strip()
        if not api_key:
            raise HaricaConfigurationError(tr("env_empty", name=location.source))
        return ResolvedCredential(api_key=api_key, source=location.source)

    return ResolvedCredential(
        api_key=read_api_key_file(location.path),
        source=location.source,
        path=location.path,
    )


def inspect_credential(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> CredentialStatus:
    """Controlla presenza e sicurezza senza restituire il valore della chiave."""
    try:
        location = select_credential_location(
            environment,
            explicit_path=explicit_path,
            environ=environ,
        )
    except HaricaConfigurationError as exc:
        return CredentialStatus(False, tr("configuration"), None, str(exc))

    try:
        if location.path is None:
            if not (location.direct_value or "").strip():
                raise HaricaConfigurationError(tr("env_empty", name=location.source))
            detail = tr("environment_variable_set")
        else:
            read_api_key_file(location.path)
            detail = tr(
                "dpapi_file_detail" if IS_WINDOWS else "secure_file_detail"
            )
    except HaricaConfigurationError as exc:
        return CredentialStatus(False, location.source, location.path, str(exc))

    return CredentialStatus(True, location.source, location.path, detail)


def read_api_key_file(path: Path | str) -> str:
    """Legge un file segreto validato e, su Windows, protetto con DPAPI."""
    target = _validated_storage_path(path)
    metadata = _validate_secret_file_metadata(target)
    try:
        content = read_stable_bytes(target, metadata)
        if IS_WINDOWS:
            content = unprotect(content, purpose="api-key")
        api_key = content.decode("utf-8").strip()
    except StoragePathError as exc:
        raise HaricaConfigurationError(
            tr("api_key_changed_during_read", path=target)
        ) from exc
    except DpapiError as exc:
        raise _dpapi_configuration_error(exc, path=target, operation="read") from exc
    except (OSError, UnicodeError) as exc:
        raise HaricaConfigurationError(
            tr("api_key_read_failed", path=target, error=exc)
        ) from exc
    if not api_key:
        raise HaricaConfigurationError(tr("api_key_file_empty", path=target))
    return api_key


def write_api_key_file(path: Path | str, api_key: str) -> Path:
    """Crea o ruota una chiave con una scrittura atomica sicura."""
    secret = api_key.strip()
    if not secret:
        raise HaricaConfigurationError(tr("api_key_empty"))

    target = _validated_storage_path(path)
    _ensure_secure_directory(target.parent)
    if target.exists() or target.is_symlink():
        _validate_secret_file_metadata(target)

    try:
        content = secret.encode("utf-8")
        if IS_WINDOWS:
            content = protect(content, purpose="api-key")
        else:
            content += b"\n"
        atomic_write_bytes(target, content)
    except DpapiError as exc:
        raise _dpapi_configuration_error(exc, path=target, operation="write") from exc
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("api_key_write_failed", path=target, error=exc)
        ) from exc
    return target


def delete_api_key_file(path: Path | str) -> Path:
    """Elimina solo un file segreto valido, senza rimuovere la directory."""
    target = _validated_storage_path(path)
    _validate_secret_file_metadata(target)
    try:
        target.unlink()
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("api_key_delete_failed", path=target, error=exc)
        ) from exc
    return target


def _validated_storage_path(path: Path | str) -> Path:
    try:
        return storage_path(path)
    except StoragePathError as exc:
        keys = {
            "windows_path_not_absolute": "windows_path_not_absolute",
            "windows_path_not_local": "windows_path_not_local",
            "reparse": "api_key_reparse",
        }
        key = keys.get(exc.reason, "windows_path_not_local")
        raise HaricaConfigurationError(tr(key, path=exc.path)) from exc


def _root_configuration_error(error: StoragePathError) -> HaricaConfigurationError:
    keys = {
        "config_root_not_absolute": (
            "windows_config_absolute" if IS_WINDOWS else "absolute_xdg"
        ),
        "home_not_absolute": "absolute_home",
    }
    return HaricaConfigurationError(
        tr(keys.get(error.reason, "windows_config_absolute"))
    )


def _validate_secret_file_metadata(path: Path):
    try:
        metadata = validate_private_file(path)
        validate_private_directory(path.parent)
        return metadata
    except FileNotFoundError as exc:
        raise HaricaConfigurationError(tr("api_key_file_missing", path=path)) from exc
    except StoragePathError as exc:
        keys = {
            "reparse": "api_key_reparse",
            "not_regular": "api_key_not_regular",
            "wrong_owner": "api_key_wrong_owner",
            "permissions": "api_key_permissions",
            "not_readable": "api_key_not_readable",
            "unsafe_directory": "credential_dir_unsafe",
        }
        key = keys.get(exc.reason, "api_key_file_check_failed")
        values = {"path": exc.path}
        if exc.mode is not None:
            values["mode"] = exc.mode
        if key == "api_key_file_check_failed":
            values["error"] = exc.reason
        raise HaricaConfigurationError(tr(key, **values)) from exc
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("api_key_file_check_failed", path=path, error=exc)
        ) from exc


def _ensure_secure_directory(path: Path) -> None:
    try:
        ensure_private_directory(path)
    except StoragePathError as exc:
        keys = {
            "unsafe_directory": "credential_dir_unsafe",
            "wrong_owner": "credential_dir_wrong_owner",
            "permissions": "credential_dir_permissions",
        }
        key = keys.get(exc.reason, "credential_dir_check_failed")
        values = {"path": exc.path}
        if exc.mode is not None:
            values["mode"] = exc.mode
        if key == "credential_dir_check_failed":
            values["error"] = exc.reason
        raise HaricaConfigurationError(tr(key, **values)) from exc
    except OSError as exc:
        raise HaricaConfigurationError(
            tr("credential_dir_create_failed", path=path, error=exc)
        ) from exc


def _dpapi_configuration_error(
    error: DpapiError,
    *,
    path: Path,
    operation: str,
) -> HaricaConfigurationError:
    if error.reason == "invalid_format":
        return HaricaConfigurationError(tr("dpapi_api_key_invalid_format", path=path))
    if operation == "write":
        return HaricaConfigurationError(
            tr("dpapi_protect_failed", path=path, error=error)
        )
    return HaricaConfigurationError(
        tr("dpapi_unprotect_failed", path=path, error=error)
    )
