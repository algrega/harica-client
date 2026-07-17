"""Cataloghi e selezione della lingua per l'interfaccia CLI."""

from __future__ import annotations

import os
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

SUPPORTED_LANGUAGES = ("it", "en")
LANGUAGE_ENV = "HARICA_CLIENT_LANGUAGE"
DEFAULT_LANGUAGE = "it"

_language: ContextVar[str] = ContextVar("harica_client_language", default=DEFAULT_LANGUAGE)


_CATALOGS: dict[str, dict[str, str]] = {
    "it": {
        "app_description": "Client prudente per le API Certificate Manager di HARICA",
        "show_help": "Mostra questo messaggio di aiuto ed esce",
        "usage": "uso",
        "positional_arguments": "argomenti posizionali",
        "options": "opzioni",
        "error": "Errore",
        "configuration_error": "Errore di configurazione",
        "response_preview": "Anteprima risposta",
        "help_language": "Lingua per questa esecuzione; sovrascrive la preferenza salvata",
        "help_language_command": "Gestisce la preferenza persistente della lingua",
        "help_language_set": "Salva la lingua predefinita",
        "help_language_status": "Mostra lingua effettiva, origine e configurazione",
        "help_language_reset": "Rimuove la preferenza di lingua salvata",
        "language_value": "Lingua da salvare",
        "language_label": "Lingua",
        "language_saved": "Lingua predefinita salvata: {language} in {path}",
        "language_reset": "Preferenza di lingua rimossa da {path}",
        "language_not_saved": "Nessuna preferenza di lingua salvata da rimuovere.",
        "language_source_flag": "opzione --language",
        "language_source_environment": "variabile HARICA_CLIENT_LANGUAGE",
        "language_source_saved": "preferenza salvata",
        "language_source_default": "valore predefinito",
        "language_file_not_regular": "Il percorso della lingua non è un file regolare: {value}",
        "language_file_wrong_owner": (
            "Il file della lingua non appartiene all'utente corrente: {value}"
        ),
        "language_file_writable": (
            "Il file della lingua è scrivibile da gruppo o altri: {value}"
        ),
        "language_directory_unsafe": "La directory della lingua non è sicura: {value}",
        "language_file_missing": "File della lingua non trovato: {value}",
        "language_io_error": (
            "Errore durante l'accesso alla configurazione della lingua: {value}"
        ),
        "help_environment": "Ambiente HARICA (default: production)",
        "help_base_url": (
            "Base URL personalizzata, utile per test locali (sovrascrive --environment)"
        ),
        "help_timeout": "Timeout HTTP in secondi",
        "help_max_attempts": "Numero totale massimo di tentativi (default: 4)",
        "help_api_key_file": (
            "File API key protetto; precede variabili d'ambiente e percorso predefinito"
        ),
        "help_auth_api_key_file": "Percorso alternativo del file API key",
        "help_json": "Stampa il JSON integrale",
        "help_csv": "Esporta tutti i campi in un file CSV UTF-8",
        "help_force": "Sovrascrive il file indicato con --csv, se esiste",
        "help_version": "Mostra la versione",
        "help_list": "Elenca certificati per stato",
        "help_status": "Stato dei certificati; all interroga i tre stati (default: valid)",
        "help_fqdn": "Filtra per FQDN, CN, SAN o DN (ricerca parziale case-insensitive)",
        "help_friendly_name": "Filtra per friendlyName (ricerca parziale case-insensitive)",
        "help_email": "Filtra per indirizzo email (ricerca parziale case-insensitive)",
        "help_serial": "Cerca un certificato per seriale",
        "serial_number": "Numero seriale del certificato",
        "help_auth": "Gestisce l'API key su filesystem",
        "help_auth_set": "Salva o ruota una API key",
        "help_auth_status": "Controlla origine e sicurezza della API key",
        "help_auth_delete": "Elimina una API key",
        "help_yes": "Conferma la cancellazione senza prompt interattivo",
        "language_missing": "l'opzione --language richiede un valore: it oppure en",
        "language_invalid": "lingua non valida: {value!r} (valori ammessi: it, en)",
        "arg_required": "sono richiesti i seguenti argomenti: {arguments}",
        "arg_unrecognized": "argomenti non riconosciuti: {arguments}",
        "arg_expected_one": "l'argomento {argument} richiede un valore",
        "arg_invalid_choice": "argomento {argument}: scelta non valida: {value} ({choices})",
        "arg_not_allowed": "argomento {argument}: non consentito insieme a {other}",
        "api_key_prompt": "API key HARICA: ",
        "api_key_repeat_prompt": "Ripetere API key HARICA: ",
        "api_keys_mismatch": "Le API key inserite non coincidono",
        "api_key_saved": "API key salvata per {environment} in {path}",
        "status": "Stato",
        "valid": "valida",
        "invalid": "non valida",
        "source": "Origine",
        "path": "Percorso",
        "permissions": "Permessi",
        "permissions_valid": "validi",
        "permissions_fix": "da correggere",
        "not_applicable": "non applicabile",
        "detail": "Dettaglio",
        "delete_prompt": "Eliminare la API key per {environment} da {path}? [s/N] ",
        "confirmation_unavailable": "Conferma interattiva non disponibile; usare --yes",
        "operation_cancelled": "Operazione annullata.",
        "api_key_deleted": "API key eliminata per {environment} da {path}",
        "rows_exported": "Esportate {count} righe in {path}",
        "empty_filter": "{option} non può essere vuoto",
        "no_results": "Nessun risultato.",
        "csv_not_rows": "La risposta HARICA non è convertibile in righe CSV; usare --json",
        "csv_exists": "Il file CSV esiste già: {path}. Usare --force per sovrascriverlo",
        "csv_write_failed": "Impossibile scrivere il CSV {path}: {error}",
        "retry_attempts_min": "max_attempts deve essere almeno 1",
        "retry_values_non_negative": (
            "I valori temporali della retry policy non possono essere negativi"
        ),
        "api_key_missing": "API key HARICA assente",
        "timeout_positive": "Il timeout deve essere maggiore di zero",
        "environment_invalid": (
            "Ambiente HARICA non valido: {environment!r}. Valori ammessi: {allowed}"
        ),
        "base_url_scheme": "La base URL deve iniziare con http:// o https://",
        "status_invalid": "Stato non valido. Valori ammessi: valid, revoked, expired, all",
        "list_format_unexpected": (
            "HARICA ha restituito un formato inatteso durante l'elenco dei certificati"
        ),
        "serial_empty": "Il numero seriale non può essere vuoto",
        "network_failed_attempts": (
            "Richiesta HARICA non riuscita dopo {attempts} tentativi: {reason}"
        ),
        "network_failed": "Richiesta HARICA non riuscita: {reason}",
        "non_json_response": "HARICA ha restituito HTTP {status_code} con un corpo non JSON",
        "auth_rejected": (
            "Autenticazione o autorizzazione HARICA rifiutata "
            "(HTTP {status_code}){suffix}"
        ),
        "retry_hint": "; riprovare tra circa {seconds:g} secondi",
        "rate_limit": "Rate limit HARICA raggiunto dopo tutti i tentativi{wait_hint}{suffix}",
        "request_rejected": "Richiesta HARICA rifiutata (HTTP {status_code}){suffix}",
        "absolute_xdg": "XDG_CONFIG_HOME deve essere un percorso assoluto",
        "absolute_home": "HOME deve essere un percorso assoluto",
        "env_empty": "{name} è definita ma vuota",
        "default_file": "file predefinito",
        "configuration": "configurazione",
        "environment_variable_set": "variabile d'ambiente valorizzata",
        "secure_file_detail": "file regolare, proprietario corretto e permessi sicuri",
        "api_key_read_failed": "Impossibile leggere il file API key {path}: {error}",
        "api_key_file_empty": "Il file API key è vuoto: {path}",
        "api_key_empty": "L'API key non può essere vuota",
        "api_key_write_failed": "Impossibile scrivere il file API key {path}: {error}",
        "api_key_delete_failed": "Impossibile eliminare il file API key {path}: {error}",
        "api_key_file_missing": "File API key non trovato: {path}",
        "api_key_file_check_failed": "Impossibile controllare il file API key {path}: {error}",
        "api_key_symlink": "Il file API key non può essere un link simbolico: {path}",
        "api_key_not_regular": "Il percorso API key non è un file regolare: {path}",
        "api_key_wrong_owner": "Il file API key non appartiene all'utente corrente: {path}",
        "api_key_permissions": (
            "Permessi non sicuri sul file API key {path}: {mode:04o}; "
            "richiesto 0600 o più restrittivo"
        ),
        "api_key_not_readable": "Il file API key non è leggibile dal proprietario: {path}",
        "credential_dir_create_failed": (
            "Impossibile creare la directory credenziali {path}: {error}"
        ),
        "credential_dir_check_failed": (
            "Impossibile controllare la directory credenziali {path}: {error}"
        ),
        "credential_dir_unsafe": "La directory credenziali non è una directory sicura: {path}",
        "credential_dir_wrong_owner": (
            "La directory credenziali non appartiene all'utente corrente: {path}"
        ),
        "credential_dir_permissions": (
            "Permessi non sicuri sulla directory credenziali {path}: {mode:04o}; "
            "richiesto 0700"
        ),
    },
    "en": {
        "app_description": "Cautious CLI client for the HARICA Certificate Manager APIs",
        "show_help": "Show this help message and exit",
        "usage": "usage",
        "positional_arguments": "positional arguments",
        "options": "options",
        "error": "Error",
        "configuration_error": "Configuration error",
        "response_preview": "Response preview",
        "help_language": "Language for this run; overrides the saved preference",
        "help_language_command": "Manage the persistent language preference",
        "help_language_set": "Save the default language",
        "help_language_status": "Show the effective language, source, and configuration",
        "help_language_reset": "Remove the saved language preference",
        "language_value": "Language to save",
        "language_label": "Language",
        "language_saved": "Default language saved: {language} in {path}",
        "language_reset": "Language preference removed from {path}",
        "language_not_saved": "There is no saved language preference to remove.",
        "language_source_flag": "--language option",
        "language_source_environment": "HARICA_CLIENT_LANGUAGE variable",
        "language_source_saved": "saved preference",
        "language_source_default": "default value",
        "language_file_not_regular": "Language path is not a regular file: {value}",
        "language_file_wrong_owner": (
            "Language file is not owned by the current user: {value}"
        ),
        "language_file_writable": (
            "Language file is writable by group or others: {value}"
        ),
        "language_directory_unsafe": (
            "Language configuration directory is unsafe: {value}"
        ),
        "language_file_missing": "Language file not found: {value}",
        "language_io_error": (
            "Error while accessing the language configuration: {value}"
        ),
        "help_environment": "HARICA environment (default: production)",
        "help_base_url": "Custom base URL for local testing (overrides --environment)",
        "help_timeout": "HTTP timeout in seconds",
        "help_max_attempts": "Maximum total number of attempts (default: 4)",
        "help_api_key_file": (
            "Protected API key file; takes precedence over environment variables "
            "and the default path"
        ),
        "help_auth_api_key_file": "Alternative API key file path",
        "help_json": "Print the complete JSON response",
        "help_csv": "Export all fields to a UTF-8 CSV file",
        "help_force": "Overwrite the file passed to --csv if it exists",
        "help_version": "Show the version",
        "help_list": "List certificates by status",
        "help_status": "Certificate status; all queries all three statuses (default: valid)",
        "help_fqdn": "Filter by FQDN, CN, SAN, or DN (case-insensitive partial match)",
        "help_friendly_name": "Filter by friendlyName (case-insensitive partial match)",
        "help_email": "Filter by email address (case-insensitive partial match)",
        "help_serial": "Find a certificate by serial number",
        "serial_number": "Certificate serial number",
        "help_auth": "Manage the API key on the filesystem",
        "help_auth_set": "Save or rotate an API key",
        "help_auth_status": "Check API key source and security",
        "help_auth_delete": "Delete an API key",
        "help_yes": "Confirm deletion without an interactive prompt",
        "language_missing": "option --language requires a value: it or en",
        "language_invalid": "invalid language: {value!r} (allowed values: it, en)",
        "arg_required": "the following arguments are required: {arguments}",
        "arg_unrecognized": "unrecognized arguments: {arguments}",
        "arg_expected_one": "argument {argument}: expected one argument",
        "arg_invalid_choice": "argument {argument}: invalid choice: {value} ({choices})",
        "arg_not_allowed": "argument {argument}: not allowed with {other}",
        "api_key_prompt": "HARICA API key: ",
        "api_key_repeat_prompt": "Repeat HARICA API key: ",
        "api_keys_mismatch": "The entered API keys do not match",
        "api_key_saved": "API key saved for {environment} in {path}",
        "status": "Status",
        "valid": "valid",
        "invalid": "invalid",
        "source": "Source",
        "path": "Path",
        "permissions": "Permissions",
        "permissions_valid": "valid",
        "permissions_fix": "must be fixed",
        "not_applicable": "not applicable",
        "detail": "Detail",
        "delete_prompt": "Delete the API key for {environment} from {path}? [y/N] ",
        "confirmation_unavailable": "Interactive confirmation is unavailable; use --yes",
        "operation_cancelled": "Operation cancelled.",
        "api_key_deleted": "API key deleted for {environment} from {path}",
        "rows_exported": "Exported {count} rows to {path}",
        "empty_filter": "{option} cannot be empty",
        "no_results": "No results.",
        "csv_not_rows": "The HARICA response cannot be converted to CSV rows; use --json",
        "csv_exists": "CSV file already exists: {path}. Use --force to overwrite it",
        "csv_write_failed": "Unable to write CSV file {path}: {error}",
        "retry_attempts_min": "max_attempts must be at least 1",
        "retry_values_non_negative": "Retry policy timing values cannot be negative",
        "api_key_missing": "HARICA API key is missing",
        "timeout_positive": "Timeout must be greater than zero",
        "environment_invalid": (
            "Invalid HARICA environment: {environment!r}. Allowed values: {allowed}"
        ),
        "base_url_scheme": "Base URL must start with http:// or https://",
        "status_invalid": "Invalid status. Allowed values: valid, revoked, expired, all",
        "list_format_unexpected": "HARICA returned an unexpected format while listing certificates",
        "serial_empty": "Serial number cannot be empty",
        "network_failed_attempts": "HARICA request failed after {attempts} attempts: {reason}",
        "network_failed": "HARICA request failed: {reason}",
        "non_json_response": "HARICA returned HTTP {status_code} with a non-JSON body",
        "auth_rejected": (
            "HARICA authentication or authorization rejected "
            "(HTTP {status_code}){suffix}"
        ),
        "retry_hint": "; retry in about {seconds:g} seconds",
        "rate_limit": "HARICA rate limit reached after all attempts{wait_hint}{suffix}",
        "request_rejected": "HARICA request rejected (HTTP {status_code}){suffix}",
        "absolute_xdg": "XDG_CONFIG_HOME must be an absolute path",
        "absolute_home": "HOME must be an absolute path",
        "env_empty": "{name} is set but empty",
        "default_file": "default file",
        "configuration": "configuration",
        "environment_variable_set": "environment variable is set",
        "secure_file_detail": "regular file, correct owner, and secure permissions",
        "api_key_read_failed": "Unable to read API key file {path}: {error}",
        "api_key_file_empty": "API key file is empty: {path}",
        "api_key_empty": "API key cannot be empty",
        "api_key_write_failed": "Unable to write API key file {path}: {error}",
        "api_key_delete_failed": "Unable to delete API key file {path}: {error}",
        "api_key_file_missing": "API key file not found: {path}",
        "api_key_file_check_failed": "Unable to inspect API key file {path}: {error}",
        "api_key_symlink": "API key file cannot be a symbolic link: {path}",
        "api_key_not_regular": "API key path is not a regular file: {path}",
        "api_key_wrong_owner": "API key file is not owned by the current user: {path}",
        "api_key_permissions": (
            "Unsafe permissions on API key file {path}: {mode:04o}; "
            "0600 or stricter is required"
        ),
        "api_key_not_readable": "API key file is not readable by its owner: {path}",
        "credential_dir_create_failed": "Unable to create credentials directory {path}: {error}",
        "credential_dir_check_failed": "Unable to inspect credentials directory {path}: {error}",
        "credential_dir_unsafe": "The credentials path is not a secure directory: {path}",
        "credential_dir_wrong_owner": (
            "Credentials directory is not owned by the current user: {path}"
        ),
        "credential_dir_permissions": (
            "Unsafe permissions on credentials directory {path}: {mode:04o}; "
            "0700 is required"
        ),
    },
}


@dataclass(frozen=True, slots=True)
class LanguageSelectionError(ValueError):
    """Errore di bootstrap traducibile prima della creazione del parser."""

    message_key: str
    value: str | None = None
    fallback_language: str = DEFAULT_LANGUAGE

    def __str__(self) -> str:
        return tr(self.message_key, value=self.value)


@dataclass(frozen=True, slots=True)
class LanguagePreference:
    """Lingua effettiva e relativa origine."""

    language: str
    source: str
    path: Path | None = None


def get_language() -> str:
    return _language.get()


@contextmanager
def using_language(language: str) -> Iterator[None]:
    token = _language.set(language)
    try:
        yield
    finally:
        _language.reset(token)


def tr(message_key: str, **values: object) -> str:
    template = _CATALOGS[get_language()][message_key]
    return template.format(**values)


def default_language_path(
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Restituisce il percorso XDG della preferenza persistente."""
    current = os.environ if environ is None else environ
    xdg_config_home = current.get("XDG_CONFIG_HOME", "").strip()
    if xdg_config_home:
        root = Path(xdg_config_home).expanduser()
        if not root.is_absolute():
            raise LanguageSelectionError("absolute_xdg")
    else:
        configured_home = current.get("HOME", "").strip()
        root = (Path(configured_home).expanduser() if configured_home else Path.home()) / ".config"
        if not root.is_absolute():
            raise LanguageSelectionError("absolute_home")
    return Path(os.path.abspath(root / "harica-client" / "language"))


def read_saved_language(
    *,
    environ: Mapping[str, str] | None = None,
) -> LanguagePreference | None:
    """Legge la preferenza persistente dopo controlli POSIX di base."""
    path = default_language_path(environ=environ)
    if not _validate_saved_language_metadata(path, missing_ok=True):
        return None
    try:
        selected = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise _language_io_error(path, exc) from exc
    if selected not in SUPPORTED_LANGUAGES:
        raise LanguageSelectionError("language_invalid", value=selected)
    return LanguagePreference(selected, "saved", path)


def _validate_saved_language_metadata(path: Path, *, missing_ok: bool) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return False
        raise LanguageSelectionError("language_file_missing", value=str(path)) from None
    except OSError as exc:
        raise _language_io_error(path, exc) from exc

    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LanguageSelectionError("language_file_not_regular", value=str(path))
    if metadata.st_uid != os.geteuid():
        raise LanguageSelectionError("language_file_wrong_owner", value=str(path))
    if metadata.st_mode & 0o022:
        raise LanguageSelectionError("language_file_writable", value=str(path))
    return True


def write_saved_language(
    language: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Salva atomicamente una preferenza con directory 0700 e file 0600."""
    if language not in SUPPORTED_LANGUAGES:
        raise LanguageSelectionError("language_invalid", value=language)
    path = default_language_path(environ=environ)
    directory = path.parent
    previous_umask = os.umask(0o077)
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise _language_io_error(directory, exc) from exc
    finally:
        os.umask(previous_umask)

    try:
        directory_metadata = directory.lstat()
    except OSError as exc:
        raise _language_io_error(directory, exc) from exc
    if (
        stat.S_ISLNK(directory_metadata.st_mode)
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != os.geteuid()
        or directory_metadata.st_mode & 0o022
    ):
        raise LanguageSelectionError("language_directory_unsafe", value=str(directory))
    if path.exists() or path.is_symlink():
        _validate_saved_language_metadata(path, missing_ok=False)

    descriptor: int | None = None
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".language.",
            suffix=".tmp",
            dir=directory,
            text=True,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = None
            stream.write(f"{language}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        os.chmod(path, 0o600)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise _language_io_error(path, exc) from exc
    return path


def delete_saved_language(
    *,
    environ: Mapping[str, str] | None = None,
) -> Path | None:
    """Rimuove la preferenza salvata; l'operazione è idempotente."""
    path = default_language_path(environ=environ)
    if not _validate_saved_language_metadata(path, missing_ok=True):
        return None
    try:
        path.unlink()
    except OSError as exc:
        raise _language_io_error(path, exc) from exc
    return path


def resolve_language_preference(
    argv: Sequence[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> LanguagePreference:
    """Risolve flag e variabile d'ambiente senza dipendere dal locale di sistema."""
    current = os.environ if environ is None else environ
    environment_value = current.get(LANGUAGE_ENV)
    fallback = (
        environment_value.strip()
        if environment_value is not None and environment_value.strip() in SUPPORTED_LANGUAGES
        else DEFAULT_LANGUAGE
    )

    explicit: str | None = None
    found_explicit = False
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--":
            break
        if item == "--language":
            found_explicit = True
            if index + 1 >= len(argv):
                raise LanguageSelectionError("language_missing", fallback_language=fallback)
            explicit = argv[index + 1].strip()
            index += 2
            continue
        if item.startswith("--language="):
            found_explicit = True
            explicit = item.partition("=")[2].strip()
        index += 1

    if found_explicit:
        if explicit not in SUPPORTED_LANGUAGES:
            raise LanguageSelectionError(
                "language_invalid",
                value=explicit,
                fallback_language=fallback,
            )
        return LanguagePreference(explicit, "flag")

    if environment_value is not None:
        selected = environment_value.strip()
        if selected not in SUPPORTED_LANGUAGES:
            raise LanguageSelectionError(
                "language_invalid",
                value=selected,
                fallback_language=DEFAULT_LANGUAGE,
            )
        return LanguagePreference(selected, "environment")

    saved = read_saved_language(environ=current)
    if saved is not None:
        return saved
    return LanguagePreference(DEFAULT_LANGUAGE, "default")


def resolve_language(
    argv: Sequence[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Restituisce soltanto il codice lingua per compatibilità interna."""
    return resolve_language_preference(argv, environ=environ).language


def _language_io_error(path: Path, error: OSError) -> LanguageSelectionError:
    return LanguageSelectionError("language_io_error", value=f"{path}: {error}")


def localize_argparse_error(message: str) -> str:
    """Traduce le forme di errore generate da argparse usate dalla CLI."""
    if get_language() == "en":
        return message

    prefixes = (
        ("the following arguments are required: ", "arg_required", "arguments"),
        ("unrecognized arguments: ", "arg_unrecognized", "arguments"),
    )
    for prefix, key, field in prefixes:
        if message.startswith(prefix):
            return tr(key, **{field: message[len(prefix) :]})

    match = re.fullmatch(r"argument (.+): expected one argument", message)
    if match:
        return tr("arg_expected_one", argument=match.group(1))

    match = re.fullmatch(
        r"argument (.+): invalid choice: (.+) \(choose from (.+)\)",
        message,
    )
    if match:
        return tr(
            "arg_invalid_choice",
            argument=match.group(1),
            value=match.group(2),
            choices=f"valori ammessi: {match.group(3)}",
        )

    match = re.fullmatch(r"argument (.+): not allowed with argument (.+)", message)
    if match:
        return tr("arg_not_allowed", argument=match.group(1), other=match.group(2))
    return message
