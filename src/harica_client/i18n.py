"""Cataloghi e selezione della lingua per l'interfaccia CLI."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
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
        "help_language": "Lingua dell'interfaccia (default: it)",
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
        "help_auth_migrate": "Migra una API key dal vecchio percorso harica-safe",
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
        "api_key_migrated": "API key migrata per {environment} da {source} a {destination}",
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
        "legacy_file": "file legacy harica-safe",
        "configuration": "configurazione",
        "new_credential_exists": "La credenziale harica-client esiste già: {path}",
        "legacy_copy_cleanup_failed": (
            "Credenziale copiata in {destination}, ma il file legacy non è stato "
            "eliminato: {error}"
        ),
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
        "help_language": "Interface language (default: it)",
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
        "help_auth_migrate": "Migrate an API key from the old harica-safe path",
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
        "api_key_migrated": "API key migrated for {environment} from {source} to {destination}",
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
        "legacy_file": "legacy harica-safe file",
        "configuration": "configuration",
        "new_credential_exists": "The harica-client credential already exists: {path}",
        "legacy_copy_cleanup_failed": (
            "Credential copied to {destination}, but the legacy file could not be "
            "deleted: {error}"
        ),
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


def resolve_language(
    argv: Sequence[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> str:
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
        return explicit

    if environment_value is None:
        return DEFAULT_LANGUAGE
    selected = environment_value.strip()
    if selected not in SUPPORTED_LANGUAGES:
        raise LanguageSelectionError(
            "language_invalid",
            value=selected,
            fallback_language=DEFAULT_LANGUAGE,
        )
    return selected


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
