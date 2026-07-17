"""Gestione portabile delle credenziali HARICA su filesystem POSIX."""

from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .errors import HaricaConfigurationError

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
    """Restituisce il percorso XDG predefinito per un ambiente HARICA."""
    current = os.environ if environ is None else environ
    xdg_config_home = current.get("XDG_CONFIG_HOME", "").strip()
    if xdg_config_home:
        root = Path(xdg_config_home).expanduser()
        if not root.is_absolute():
            raise HaricaConfigurationError("XDG_CONFIG_HOME deve essere un percorso assoluto")
    else:
        configured_home = current.get("HOME", "").strip()
        root = (Path(configured_home).expanduser() if configured_home else Path.home()) / ".config"
        if not root.is_absolute():
            raise HaricaConfigurationError("HOME deve essere un percorso assoluto")
    return _absolute_path(root / "harica-client" / "credentials" / f"{environment}.key")


def legacy_default_api_key_path(
    environment: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Percorso usato da harica-safe, mantenuto solo per migrazione."""
    current = os.environ if environ is None else environ
    xdg_config_home = current.get("XDG_CONFIG_HOME", "").strip()
    if xdg_config_home:
        root = Path(xdg_config_home).expanduser()
        if not root.is_absolute():
            raise HaricaConfigurationError("XDG_CONFIG_HOME deve essere un percorso assoluto")
    else:
        configured_home = current.get("HOME", "").strip()
        root = (Path(configured_home).expanduser() if configured_home else Path.home()) / ".config"
        if not root.is_absolute():
            raise HaricaConfigurationError("HOME deve essere un percorso assoluto")
    return _absolute_path(root / "harica-safe" / "credentials" / f"{environment}.key")


def select_credential_location(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> CredentialLocation:
    """Seleziona la sorgente senza leggere né mostrare il segreto."""
    current = os.environ if environ is None else environ
    if explicit_path is not None:
        return CredentialLocation(source="--api-key-file", path=_absolute_path(explicit_path))
    if API_KEY_ENV in current:
        return CredentialLocation(source=API_KEY_ENV, direct_value=current[API_KEY_ENV])
    if API_KEY_FILE_ENV in current:
        configured = current[API_KEY_FILE_ENV].strip()
        if not configured:
            raise HaricaConfigurationError(f"{API_KEY_FILE_ENV} è definita ma vuota")
        return CredentialLocation(source=API_KEY_FILE_ENV, path=_absolute_path(configured))
    preferred = default_api_key_path(environment, environ=current)
    if preferred.exists() or preferred.is_symlink():
        return CredentialLocation(source="file predefinito", path=preferred)
    legacy = legacy_default_api_key_path(environment, environ=current)
    if legacy.exists() or legacy.is_symlink():
        return CredentialLocation(source="file legacy harica-safe", path=legacy)
    return CredentialLocation(source="file predefinito", path=preferred)


def credential_destination(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Seleziona la destinazione per set/delete, ignorando HARICA_API_KEY."""
    current = os.environ if environ is None else environ
    if explicit_path is not None:
        return _absolute_path(explicit_path)
    if API_KEY_FILE_ENV in current:
        configured = current[API_KEY_FILE_ENV].strip()
        if not configured:
            raise HaricaConfigurationError(f"{API_KEY_FILE_ENV} è definita ma vuota")
        return _absolute_path(configured)
    return default_api_key_path(environment, environ=current)


def credential_deletion_target(
    environment: str,
    *,
    explicit_path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Seleziona il file nuovo o, se assente, il file legacy da eliminare."""
    current = os.environ if environ is None else environ
    if explicit_path is not None or API_KEY_FILE_ENV in current:
        return credential_destination(
            environment,
            explicit_path=explicit_path,
            environ=current,
        )
    preferred = default_api_key_path(environment, environ=current)
    if preferred.exists() or preferred.is_symlink():
        return preferred
    legacy = legacy_default_api_key_path(environment, environ=current)
    if legacy.exists() or legacy.is_symlink():
        return legacy
    return preferred


def migrate_legacy_api_key(
    environment: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> tuple[Path, Path]:
    """Sposta atomicamente una credenziale harica-safe nel nuovo percorso."""
    current = os.environ if environ is None else environ
    source = legacy_default_api_key_path(environment, environ=current)
    destination = default_api_key_path(environment, environ=current)
    if destination.exists() or destination.is_symlink():
        raise HaricaConfigurationError(
            f"La credenziale harica-client esiste già: {destination}"
        )

    api_key = read_api_key_file(source)
    write_api_key_file(destination, api_key)
    try:
        delete_api_key_file(source)
    except HaricaConfigurationError as exc:
        raise HaricaConfigurationError(
            f"Credenziale copiata in {destination}, ma il file legacy non è stato eliminato: {exc}"
        ) from exc

    _remove_empty_legacy_directories(source.parent)
    return source, destination


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
            raise HaricaConfigurationError(f"{location.source} è definita ma vuota")
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
        return CredentialStatus(False, "configurazione", None, str(exc))

    try:
        if location.path is None:
            if not (location.direct_value or "").strip():
                raise HaricaConfigurationError(f"{location.source} è definita ma vuota")
            detail = "variabile d'ambiente valorizzata"
        else:
            read_api_key_file(location.path)
            detail = "file regolare, proprietario corretto e permessi sicuri"
    except HaricaConfigurationError as exc:
        return CredentialStatus(False, location.source, location.path, str(exc))

    return CredentialStatus(True, location.source, location.path, detail)


def read_api_key_file(path: Path | str) -> str:
    """Legge un file segreto dopo controlli POSIX stretti."""
    target = _absolute_path(path)
    _validate_secret_file_metadata(target)
    try:
        api_key = target.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HaricaConfigurationError(
            f"Impossibile leggere il file API key {target}: {exc}"
        ) from exc
    if not api_key:
        raise HaricaConfigurationError(f"Il file API key è vuoto: {target}")
    return api_key


def write_api_key_file(path: Path | str, api_key: str) -> Path:
    """Crea o ruota una chiave con scrittura atomica e permessi 0600."""
    secret = api_key.strip()
    if not secret:
        raise HaricaConfigurationError("L'API key non può essere vuota")

    target = _absolute_path(path)
    _ensure_secure_directory(target.parent)
    if target.exists() or target.is_symlink():
        _validate_secret_file_metadata(target)

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
            stream.write(secret)
            stream.write("\n")
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
            f"Impossibile scrivere il file API key {target}: {exc}"
        ) from exc

    return target


def delete_api_key_file(path: Path | str) -> Path:
    """Elimina solo un file segreto valido, senza rimuovere la directory."""
    target = _absolute_path(path)
    _validate_secret_file_metadata(target)
    try:
        target.unlink()
    except OSError as exc:
        raise HaricaConfigurationError(
            f"Impossibile eliminare il file API key {target}: {exc}"
        ) from exc
    return target


def _absolute_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _validate_secret_file_metadata(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise HaricaConfigurationError(f"File API key non trovato: {path}") from exc
    except OSError as exc:
        raise HaricaConfigurationError(
            f"Impossibile controllare il file API key {path}: {exc}"
        ) from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise HaricaConfigurationError(f"Il file API key non può essere un link simbolico: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise HaricaConfigurationError(f"Il percorso API key non è un file regolare: {path}")
    if metadata.st_uid != os.geteuid():
        raise HaricaConfigurationError(
            f"Il file API key non appartiene all'utente corrente: {path}"
        )
    if metadata.st_mode & 0o077:
        mode = stat.S_IMODE(metadata.st_mode)
        raise HaricaConfigurationError(
            f"Permessi non sicuri sul file API key {path}: {mode:04o}; "
            "richiesto 0600 o più restrittivo"
        )
    if not metadata.st_mode & stat.S_IRUSR:
        raise HaricaConfigurationError(f"Il file API key non è leggibile dal proprietario: {path}")
    _validate_secret_directory_metadata(path.parent)


def _ensure_secure_directory(path: Path) -> None:
    previous_umask = os.umask(0o077)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise HaricaConfigurationError(
            f"Impossibile creare la directory credenziali {path}: {exc}"
        ) from exc
    finally:
        os.umask(previous_umask)

    _validate_secret_directory_metadata(path)


def _validate_secret_directory_metadata(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HaricaConfigurationError(
            f"Impossibile controllare la directory credenziali {path}: {exc}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise HaricaConfigurationError(
            f"La directory credenziali non è una directory sicura: {path}"
        )
    if metadata.st_uid != os.geteuid():
        raise HaricaConfigurationError(
            f"La directory credenziali non appartiene all'utente corrente: {path}"
        )
    if metadata.st_mode & 0o077:
        mode = stat.S_IMODE(metadata.st_mode)
        raise HaricaConfigurationError(
            f"Permessi non sicuri sulla directory credenziali {path}: {mode:04o}; richiesto 0700"
        )


def _remove_empty_legacy_directories(credentials_directory: Path) -> None:
    """Rimuove solo le directory legacy note e già vuote."""
    for directory in (credentials_directory, credentials_directory.parent):
        try:
            directory.rmdir()
        except OSError:
            break
