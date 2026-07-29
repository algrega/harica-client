"""Primitive multipiattaforma per lo storage locale sicuro."""

from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


IS_WINDOWS = os.name == "nt"


@dataclass(frozen=True, slots=True)
class StoragePathError(Exception):
    """Errore strutturato di validazione di un percorso locale."""

    reason: str
    path: Path
    mode: int | None = None


def config_root(environ: Mapping[str, str]) -> Path:
    """Restituisce la radice di configurazione nativa della piattaforma."""
    if IS_WINDOWS:
        configured = environ.get("APPDATA", "").strip()
        root = Path(configured).expanduser() if configured else Path.home() / "AppData/Roaming"
        if not root.is_absolute():
            raise StoragePathError("config_root_not_absolute", root)
        return storage_path(root)

    configured = environ.get("XDG_CONFIG_HOME", "").strip()
    if configured:
        root = Path(configured).expanduser()
        if not root.is_absolute():
            raise StoragePathError("config_root_not_absolute", root)
    else:
        home = environ.get("HOME", "").strip()
        root = (Path(home).expanduser() if home else Path.home()) / ".config"
        if not root.is_absolute():
            raise StoragePathError("home_not_absolute", root)
    return absolute_path(root)


def cache_root(environ: Mapping[str, str]) -> Path:
    """Restituisce la radice cache nativa della piattaforma."""
    if IS_WINDOWS:
        configured = environ.get("LOCALAPPDATA", "").strip()
        root = Path(configured).expanduser() if configured else Path.home() / "AppData/Local"
        if not root.is_absolute():
            raise StoragePathError("cache_root_not_absolute", root)
        return storage_path(root)

    configured = environ.get("XDG_CACHE_HOME", "").strip()
    if configured:
        root = Path(configured).expanduser()
        if not root.is_absolute():
            raise StoragePathError("cache_root_not_absolute", root)
    else:
        home = environ.get("HOME", "").strip()
        root = (Path(home).expanduser() if home else Path.home()) / ".cache"
        if not root.is_absolute():
            raise StoragePathError("home_not_absolute", root)
    return absolute_path(root)


def storage_path(path: Path | str) -> Path:
    """Normalizza un percorso, rifiutando su Windows path relativi o non locali."""
    expanded = Path(os.path.expanduser(str(path)))
    if IS_WINDOWS:
        rendered = str(expanded)
        if not expanded.is_absolute():
            raise StoragePathError("windows_path_not_absolute", expanded)
        if rendered.startswith(("\\\\", "//")):
            raise StoragePathError("windows_path_not_local", expanded)
    normalized = absolute_path(expanded)
    if IS_WINDOWS:
        drive = normalized.drive
        for part in normalized.parts:
            if (
                ":" in part
                and part.rstrip("\\/").casefold() != drive.casefold()
            ):
                raise StoragePathError("windows_path_not_local", normalized)
        _validate_windows_ancestors(normalized)
    return normalized


def absolute_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def is_reparse_point(metadata: os.stat_result) -> bool:
    """Riconosce link POSIX e reparse point Windows, incluse le junction."""
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _validate_windows_ancestors(path: Path) -> None:
    """Rifiuta reparse point in qualunque componente esistente del percorso."""
    candidates = (path, *path.parents)
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if is_reparse_point(metadata):
            raise StoragePathError("reparse", path)


def validate_private_file(path: Path) -> os.stat_result:
    """Valida tipo, proprietario e accesso di un file sensibile."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise
    except OSError:
        raise
    if is_reparse_point(metadata):
        raise StoragePathError("reparse", path)
    if not stat.S_ISREG(metadata.st_mode):
        raise StoragePathError("not_regular", path)
    if not IS_WINDOWS:
        if metadata.st_uid != os.geteuid():
            raise StoragePathError("wrong_owner", path)
        if metadata.st_mode & 0o077:
            raise StoragePathError("permissions", path, stat.S_IMODE(metadata.st_mode))
        if not metadata.st_mode & stat.S_IRUSR:
            raise StoragePathError("not_readable", path)
    return metadata


def validate_private_directory(path: Path) -> os.stat_result:
    """Valida una directory destinata a dati locali sensibili."""
    metadata = path.lstat()
    if is_reparse_point(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise StoragePathError("unsafe_directory", path)
    if not IS_WINDOWS:
        if metadata.st_uid != os.geteuid():
            raise StoragePathError("wrong_owner", path)
        if metadata.st_mode & 0o077:
            raise StoragePathError("permissions", path, stat.S_IMODE(metadata.st_mode))
    return metadata


def ensure_private_directory(path: Path) -> None:
    """Crea una directory privata conservando le garanzie POSIX esistenti."""
    if IS_WINDOWS:
        path.mkdir(parents=True, exist_ok=True)
    else:
        previous_umask = os.umask(0o077)
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        finally:
            os.umask(previous_umask)
    validate_private_directory(path)


def read_stable_bytes(path: Path, metadata: os.stat_result) -> bytes:
    """Legge un file verificando che non sia cambiato dopo il controllo."""
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise StoragePathError("changed_during_read", path)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            return stream.read()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def atomic_write_bytes(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    """Scrive byte nella stessa directory e sostituisce atomicamente la destinazione."""
    descriptor: int | None = None
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        if not IS_WINDOWS:
            os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        if not IS_WINDOWS:
            os.chmod(path, mode)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
