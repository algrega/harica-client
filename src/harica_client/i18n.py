"""Cataloghi e selezione della lingua per l'interfaccia CLI."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .platform_storage import (
    IS_WINDOWS,
    StoragePathError,
    atomic_write_bytes,
    config_root,
    ensure_private_directory,
    is_reparse_point,
    read_stable_bytes,
    storage_path,
)

SUPPORTED_LANGUAGES = ("it", "en")
LANGUAGE_ENV = "HARICA_CLIENT_LANGUAGE"
DEFAULT_LANGUAGE = "it"

_language: ContextVar[str] = ContextVar("harica_client_language", default=DEFAULT_LANGUAGE)


_CATALOGS: dict[str, dict[str, str]] = {
    "it": {
        "app_description": (
            "Client e CLI non ufficiali, in sola lettura, per consultare i certificati "
            "tramite l'API Certificate Manager di HARICA"
        ),
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
        "help_json": "Stampa l'output JSON della CLI, senza il campo certificate",
        "help_stats_json": "Stampa il report in formato JSON",
        "help_csv": "Esporta l'output della CLI in un file CSV UTF-8",
        "help_force": "Sovrascrive il file indicato con --csv, se esiste",
        "help_cache": "Gestisce la cache locale protetta dei certificati",
        "help_cache_refresh": "Aggiorna la cache interrogando tutti gli stati HARICA",
        "help_cache_status": "Mostra validità, origine, età e contenuto della cache",
        "help_cache_delete": "Elimina la cache locale",
        "help_cache_file": "Percorso alternativo del file cache protetto",
        "help_from_cache": "Legge e filtra la cache locale senza contattare HARICA",
        "help_max_cache_age": "Età massima accettata della cache, in ore",
        "help_stats": "Calcola statistiche usando esclusivamente la cache locale",
        "help_stats_summary": "Mostra il riepilogo generale dei certificati",
        "help_stats_expirations": "Elenca i certificati validi prossimi alla scadenza",
        "help_stats_owners": "Raggruppa i certificati per responsabile",
        "help_stats_quality": "Individua dati mancanti o incoerenti",
        "help_stats_within": "Intervallo di scadenza in giorni (default: 30)",
        "help_version": "Mostra la versione",
        "help_list": "Elenca certificati per stato",
        "help_status": "Stato dei certificati; all include i tre stati (default: valid)",
        "help_fqdn": "Filtra per FQDN, CN, SAN o DN (ricerca parziale case-insensitive)",
        "help_friendly_name": "Filtra per friendlyName (ricerca parziale case-insensitive)",
        "help_email": "Filtra per indirizzo email (ricerca parziale case-insensitive)",
        "help_serial": "Cerca un certificato per seriale",
        "help_download": "Scarica un certificato X.509 PEM e ne mostra il riepilogo",
        "help_download_output": (
            "File PEM di destinazione; se omesso usa un nome derivato dal CN"
        ),
        "help_download_force": "Sovrascrive il file PEM se esiste",
        "download_summary_path": "Percorso",
        "download_summary_serial": "Seriale",
        "download_summary_subject": "Soggetto",
        "download_summary_issuer": "Emittente",
        "download_summary_valid_from": "Valido dal",
        "download_summary_valid_until": "Valido fino al",
        "download_common_name_ambiguous": (
            "Il certificato contiene più CN differenti; specificare --output"
        ),
        "download_current_directory_failed": (
            "Impossibile determinare la directory corrente: {error}"
        ),
        "serial_number": "Numero seriale del certificato",
        "help_auth": "Gestisce l'API key su filesystem",
        "help_auth_set": "Salva o ruota un'API key",
        "help_auth_status": "Controlla origine e sicurezza dell'API key",
        "help_auth_delete": "Elimina un'API key",
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
        "delete_prompt": "Eliminare l'API key per {environment} da {path}? [s/N] ",
        "confirmation_unavailable": "Conferma interattiva non disponibile; usare --yes",
        "operation_cancelled": "Operazione annullata.",
        "api_key_deleted": "API key eliminata per {environment} da {path}",
        "cache_saved": (
            "Cache aggiornata per {environment}: {count} certificati in {path}"
        ),
        "cache_deleted": "Cache eliminata per {environment} da {path}",
        "cache_delete_prompt": (
            "Eliminare la cache per {environment} da {path}? [s/N] "
        ),
        "cache_environment": "Ambiente cache",
        "cache_base_url": "Origine HARICA",
        "cache_created_at": "Creata il",
        "cache_age_hours": "Età (ore)",
        "cache_certificates": "Certificati",
        "stats_within_positive": "--within deve essere un intero maggiore di zero",
        "stats_expirations_skipped": (
            "Avviso: esclusi {count} certificati validi con data di scadenza "
            "mancante o non valida."
        ),
        "stats_missing_owner": "(responsabile mancante)",
        "stats_column_metric": "Metrica",
        "stats_column_value": "Valore",
        "stats_column_serial": "Seriale",
        "stats_column_cn": "CN",
        "stats_column_friendly_name": "Nome descrittivo",
        "stats_column_email": "Email",
        "stats_column_user": "Responsabile",
        "stats_column_valid_to": "Scadenza UTC",
        "stats_column_days_remaining": "Giorni rimanenti",
        "stats_column_total": "Totale",
        "stats_column_valid": "Validi",
        "stats_column_revoked": "Revocati",
        "stats_column_expired": "Scaduti",
        "stats_column_unknown": "Sconosciuti",
        "stats_column_expiring_30": "In scadenza entro 30 giorni",
        "stats_column_issue": "Anomalia",
        "stats_metric_cache_created_at": "Data cache (UTC)",
        "stats_metric_cache_age": "Età cache (ore)",
        "stats_metric_cache_environment": "Ambiente cache",
        "stats_metric_cache_source": "Origine HARICA",
        "stats_metric_total": "Totale certificati",
        "stats_metric_valid": "Certificati validi",
        "stats_metric_revoked": "Certificati revocati",
        "stats_metric_expired": "Certificati scaduti",
        "stats_metric_unknown": "Certificati con stato sconosciuto",
        "stats_metric_expiry_0_7": "Validi in scadenza tra 0 e 7 giorni",
        "stats_metric_expiry_8_30": "Validi in scadenza tra 8 e 30 giorni",
        "stats_metric_expiry_31_60": "Validi in scadenza tra 31 e 60 giorni",
        "stats_metric_expiry_61_90": "Validi in scadenza tra 61 e 90 giorni",
        "stats_metric_expiry_over_90": "Validi con oltre 90 giorni residui",
        "stats_metric_revoked_30": "Revoche negli ultimi 30 giorni",
        "stats_metric_missing_user": "Record senza responsabile",
        "stats_metric_missing_email": "Record senza email",
        "stats_metric_missing_cn": "Record senza CN",
        "stats_metric_invalid_dates": "Record con date mancanti o non valide",
        "cache_file_requires_from_cache": (
            "--cache-file con list richiede --from-cache"
        ),
        "cache_age_requires_from_cache": (
            "--max-cache-age con list richiede --from-cache"
        ),
        "cache_custom_url_requires_file": (
            "cache refresh con --base-url richiede --cache-file esplicito"
        ),
        "cache_absolute_xdg": "XDG_CACHE_HOME deve essere un percorso assoluto",
        "cache_absolute_home": "HOME deve produrre un percorso cache assoluto",
        "windows_cache_absolute": (
            "LOCALAPPDATA deve essere un percorso Windows locale e assoluto"
        ),
        "windows_path_not_absolute": (
            "Su Windows il percorso deve essere assoluto: {path}"
        ),
        "windows_path_not_local": (
            "I percorsi UNC e device non sono supportati per credenziali o cache: {path}"
        ),
        "cache_not_serializable": "I certificati non sono serializzabili in JSON: {error}",
        "cache_response_invalid": (
            "La risposta HARICA non è utilizzabile per creare la cache"
        ),
        "cache_write_failed": "Impossibile scrivere la cache {path}: {error}",
        "cache_read_failed": "Impossibile leggere la cache {path}: {error}",
        "cache_delete_failed": "Impossibile eliminare la cache {path}: {error}",
        "cache_missing": "File cache non trovato: {path}",
        "cache_empty": "Il file cache è vuoto: {path}",
        "cache_invalid_json": "Il file cache non contiene JSON valido: {path}",
        "cache_invalid_structure": "Struttura della cache non valida: {path}",
        "cache_schema_unsupported": (
            "Versione schema cache non supportata: {actual!r}; attesa {expected}"
        ),
        "cache_invalid_timestamp": "Timestamp della cache non valido: {path}",
        "cache_timestamp_future": "Il timestamp della cache è nel futuro: {path}",
        "cache_datetime_timezone": "Il timestamp della cache deve includere il fuso orario",
        "cache_incomplete_statuses": (
            "La cache non contiene tutti gli stati richiesti: {path}"
        ),
        "cache_environment_mismatch": (
            "La cache appartiene all'ambiente {actual!r}, non a {expected!r}"
        ),
        "cache_max_age_positive": "--max-cache-age deve essere maggiore di zero",
        "cache_too_old": (
            "Cache troppo vecchia: {age_hours:.2f} ore; limite {max_age_hours:g} ore"
        ),
        "cache_changed_during_read": "Il file cache è cambiato durante la lettura: {path}",
        "cache_check_failed": "Impossibile controllare la cache {path}: {error}",
        "cache_symlink": "Il file cache non può essere un link simbolico: {path}",
        "cache_reparse": (
            "Il file cache non può essere un link, una junction o un reparse point: {path}"
        ),
        "cache_not_regular": "Il percorso cache non è un file regolare: {path}",
        "cache_wrong_owner": "Il file cache non appartiene all'utente corrente: {path}",
        "cache_permissions": (
            "Permessi non sicuri sul file cache {path}: {mode:04o}; richiesto 0600"
        ),
        "cache_not_readable": "Il file cache non è leggibile dal proprietario: {path}",
        "cache_dir_create_failed": "Impossibile creare la directory cache {path}: {error}",
        "cache_dir_check_failed": "Impossibile controllare la directory cache {path}: {error}",
        "cache_dir_unsafe": "La directory cache non è sicura: {path}",
        "cache_dir_wrong_owner": (
            "La directory cache non appartiene all'utente corrente: {path}"
        ),
        "cache_dir_permissions": (
            "Permessi non sicuri sulla directory cache {path}: {mode:04o}; richiesto 0700"
        ),
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
        "base_url_scheme": "La base URL deve usare lo schema https:// o http:// locale",
        "base_url_invalid": "La base URL non è valida",
        "base_url_host": "La base URL deve contenere un host",
        "base_url_userinfo": "La base URL non può contenere credenziali",
        "base_url_components": "La base URL non può contenere query o fragment",
        "base_url_https": "La base URL deve usare HTTPS; HTTP è consentito solo su loopback",
        "status_invalid": "Stato non valido. Valori ammessi: valid, revoked, expired, all",
        "list_format_unexpected": (
            "HARICA ha restituito un formato inatteso durante l'elenco dei certificati"
        ),
        "serial_empty": "Il numero seriale non può essere vuoto",
        "download_certificate_missing": (
            "La risposta HARICA non contiene il campo certificate"
        ),
        "download_certificate_not_text": (
            "Il campo certificate nella risposta HARICA non è testuale"
        ),
        "download_certificate_empty": (
            "Il campo certificate nella risposta HARICA è vuoto"
        ),
        "download_certificate_ambiguous": (
            "La risposta HARICA contiene più certificati differenti"
        ),
        "download_certificate_invalid": (
            "Il campo certificate non contiene un certificato X.509 valido"
        ),
        "download_multiple_certificates": (
            "Il download contiene più certificati o una chain; è ammesso un solo certificato"
        ),
        "download_private_key_rejected": (
            "Il download contiene una chiave privata e non può essere salvato"
        ),
        "download_format_unsupported": (
            "Il formato del certificato non è supportato; sono ammessi PEM o DER in base64"
        ),
        "download_destination_check_failed": (
            "Impossibile controllare la destinazione {path}: {error}"
        ),
        "download_destination_symlink": (
            "La destinazione non può essere un link simbolico: {path}"
        ),
        "download_destination_not_regular": (
            "La destinazione esistente non è un file regolare: {path}"
        ),
        "download_destination_exists": (
            "Il file di destinazione esiste già: {path}. Usare --force per sovrascriverlo"
        ),
        "download_directory_create_failed": (
            "Impossibile creare la directory di destinazione {path}: {error}"
        ),
        "download_directory_not_directory": (
            "Il percorso di destinazione non è una directory: {path}"
        ),
        "download_write_failed": (
            "Impossibile scrivere il certificato in {path}: {error}"
        ),
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
        "windows_config_absolute": (
            "APPDATA deve essere un percorso Windows locale e assoluto"
        ),
        "env_empty": "{name} è definita ma vuota",
        "default_file": "file predefinito",
        "configuration": "configurazione",
        "environment_variable_set": "variabile d'ambiente valorizzata",
        "secure_file_detail": "file regolare, proprietario corretto e permessi sicuri",
        "dpapi_file_detail": (
            "file cifrato e autenticato con DPAPI per l'utente Windows corrente"
        ),
        "api_key_read_failed": "Impossibile leggere il file API key {path}: {error}",
        "api_key_file_empty": "Il file API key è vuoto: {path}",
        "api_key_empty": "L'API key non può essere vuota",
        "api_key_write_failed": "Impossibile scrivere il file API key {path}: {error}",
        "api_key_delete_failed": "Impossibile eliminare il file API key {path}: {error}",
        "api_key_file_missing": "File API key non trovato: {path}",
        "api_key_file_check_failed": "Impossibile controllare il file API key {path}: {error}",
        "api_key_symlink": "Il file API key non può essere un link simbolico: {path}",
        "api_key_reparse": (
            "Il file API key non può essere un link, una junction o un reparse point: {path}"
        ),
        "api_key_changed_during_read": (
            "Il file API key è cambiato durante la lettura: {path}"
        ),
        "dpapi_api_key_invalid_format": (
            "Il file API key non è un contenitore DPAPI valido: {path}. "
            "Crearlo con 'harica-client auth set' oppure usare HARICA_API_KEY "
            "per automazioni effimere"
        ),
        "dpapi_cache_invalid_format": (
            "Il file cache non è un contenitore DPAPI valido: {path}; "
            "ricrearlo con 'harica-client cache refresh'"
        ),
        "dpapi_protect_failed": (
            "Windows non ha potuto proteggere con DPAPI il file {path}: {error}"
        ),
        "dpapi_unprotect_failed": (
            "Windows non ha potuto decifrare il file DPAPI {path}: {error}. "
            "Il file può essere manomesso o appartenere a un altro utente o computer"
        ),
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
        "app_description": (
            "Unofficial read-only client and CLI for querying certificates through "
            "the HARICA Certificate Manager API"
        ),
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
        "help_json": "Print the CLI JSON output without the certificate field",
        "help_stats_json": "Print the report as JSON",
        "help_csv": "Export the CLI output to a UTF-8 CSV file",
        "help_force": "Overwrite the file passed to --csv if it exists",
        "help_cache": "Manage the protected local certificate cache",
        "help_cache_refresh": "Refresh the cache by querying every HARICA status",
        "help_cache_status": "Show cache validity, source, age, and contents",
        "help_cache_delete": "Delete the local cache",
        "help_cache_file": "Alternative protected cache file path",
        "help_from_cache": "Read and filter the local cache without contacting HARICA",
        "help_max_cache_age": "Maximum accepted cache age in hours",
        "help_stats": "Calculate statistics using only the local cache",
        "help_stats_summary": "Show the overall certificate summary",
        "help_stats_expirations": "List valid certificates approaching expiration",
        "help_stats_owners": "Group certificates by owner",
        "help_stats_quality": "Find missing or inconsistent data",
        "help_stats_within": "Expiration interval in days (default: 30)",
        "help_version": "Show the version",
        "help_list": "List certificates by status",
        "help_status": "Certificate status; all includes all three statuses (default: valid)",
        "help_fqdn": "Filter by FQDN, CN, SAN, or DN (case-insensitive partial match)",
        "help_friendly_name": "Filter by friendlyName (case-insensitive partial match)",
        "help_email": "Filter by email address (case-insensitive partial match)",
        "help_serial": "Find a certificate by serial number",
        "help_download": "Download an X.509 PEM certificate and show its summary",
        "help_download_output": (
            "Destination PEM file; if omitted, use a name derived from the CN"
        ),
        "help_download_force": "Overwrite the PEM file if it exists",
        "download_summary_path": "Path",
        "download_summary_serial": "Serial",
        "download_summary_subject": "Subject",
        "download_summary_issuer": "Issuer",
        "download_summary_valid_from": "Valid from",
        "download_summary_valid_until": "Valid until",
        "download_common_name_ambiguous": (
            "The certificate contains multiple different CN values; specify --output"
        ),
        "download_current_directory_failed": (
            "Unable to determine the current directory: {error}"
        ),
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
        "cache_saved": (
            "Cache refreshed for {environment}: {count} certificates in {path}"
        ),
        "cache_deleted": "Cache deleted for {environment} from {path}",
        "cache_delete_prompt": (
            "Delete the cache for {environment} from {path}? [y/N] "
        ),
        "cache_environment": "Cache environment",
        "cache_base_url": "HARICA source",
        "cache_created_at": "Created at",
        "cache_age_hours": "Age (hours)",
        "cache_certificates": "Certificates",
        "stats_within_positive": "--within must be an integer greater than zero",
        "stats_expirations_skipped": (
            "Warning: excluded {count} valid certificates with a missing or invalid "
            "expiration date."
        ),
        "stats_missing_owner": "(missing owner)",
        "stats_column_metric": "Metric",
        "stats_column_value": "Value",
        "stats_column_serial": "Serial",
        "stats_column_cn": "CN",
        "stats_column_friendly_name": "Friendly name",
        "stats_column_email": "Email",
        "stats_column_user": "Owner",
        "stats_column_valid_to": "Expiration UTC",
        "stats_column_days_remaining": "Days remaining",
        "stats_column_total": "Total",
        "stats_column_valid": "Valid",
        "stats_column_revoked": "Revoked",
        "stats_column_expired": "Expired",
        "stats_column_unknown": "Unknown",
        "stats_column_expiring_30": "Expiring within 30 days",
        "stats_column_issue": "Issue",
        "stats_metric_cache_created_at": "Cache date (UTC)",
        "stats_metric_cache_age": "Cache age (hours)",
        "stats_metric_cache_environment": "Cache environment",
        "stats_metric_cache_source": "HARICA source",
        "stats_metric_total": "Total certificates",
        "stats_metric_valid": "Valid certificates",
        "stats_metric_revoked": "Revoked certificates",
        "stats_metric_expired": "Expired certificates",
        "stats_metric_unknown": "Certificates with unknown status",
        "stats_metric_expiry_0_7": "Valid certificates expiring in 0 to 7 days",
        "stats_metric_expiry_8_30": "Valid certificates expiring in 8 to 30 days",
        "stats_metric_expiry_31_60": "Valid certificates expiring in 31 to 60 days",
        "stats_metric_expiry_61_90": "Valid certificates expiring in 61 to 90 days",
        "stats_metric_expiry_over_90": "Valid certificates with over 90 days remaining",
        "stats_metric_revoked_30": "Revocations in the last 30 days",
        "stats_metric_missing_user": "Records without owner",
        "stats_metric_missing_email": "Records without email",
        "stats_metric_missing_cn": "Records without CN",
        "stats_metric_invalid_dates": "Records with missing or invalid dates",
        "cache_file_requires_from_cache": (
            "--cache-file with list requires --from-cache"
        ),
        "cache_age_requires_from_cache": (
            "--max-cache-age with list requires --from-cache"
        ),
        "cache_custom_url_requires_file": (
            "cache refresh with --base-url requires an explicit --cache-file"
        ),
        "cache_absolute_xdg": "XDG_CACHE_HOME must be an absolute path",
        "cache_absolute_home": "HOME must produce an absolute cache path",
        "windows_cache_absolute": (
            "LOCALAPPDATA must be a local absolute Windows path"
        ),
        "windows_path_not_absolute": (
            "On Windows, the path must be absolute: {path}"
        ),
        "windows_path_not_local": (
            "UNC and device paths are unsupported for credentials or cache: {path}"
        ),
        "cache_not_serializable": "Certificates cannot be serialized as JSON: {error}",
        "cache_response_invalid": (
            "The HARICA response cannot be used to create the cache"
        ),
        "cache_write_failed": "Unable to write cache file {path}: {error}",
        "cache_read_failed": "Unable to read cache file {path}: {error}",
        "cache_delete_failed": "Unable to delete cache file {path}: {error}",
        "cache_missing": "Cache file not found: {path}",
        "cache_empty": "Cache file is empty: {path}",
        "cache_invalid_json": "Cache file does not contain valid JSON: {path}",
        "cache_invalid_structure": "Invalid cache structure: {path}",
        "cache_schema_unsupported": (
            "Unsupported cache schema version: {actual!r}; expected {expected}"
        ),
        "cache_invalid_timestamp": "Invalid cache timestamp: {path}",
        "cache_timestamp_future": "Cache timestamp is in the future: {path}",
        "cache_datetime_timezone": "Cache timestamp must include a time zone",
        "cache_incomplete_statuses": (
            "Cache does not contain every required status: {path}"
        ),
        "cache_environment_mismatch": (
            "Cache belongs to environment {actual!r}, not {expected!r}"
        ),
        "cache_max_age_positive": "--max-cache-age must be greater than zero",
        "cache_too_old": (
            "Cache is too old: {age_hours:.2f} hours; limit {max_age_hours:g} hours"
        ),
        "cache_changed_during_read": "Cache file changed while being read: {path}",
        "cache_check_failed": "Unable to inspect cache file {path}: {error}",
        "cache_symlink": "Cache file cannot be a symbolic link: {path}",
        "cache_reparse": (
            "Cache file cannot be a link, junction, or reparse point: {path}"
        ),
        "cache_not_regular": "Cache path is not a regular file: {path}",
        "cache_wrong_owner": "Cache file is not owned by the current user: {path}",
        "cache_permissions": (
            "Unsafe cache file permissions for {path}: {mode:04o}; 0600 required"
        ),
        "cache_not_readable": "Cache file is not readable by its owner: {path}",
        "cache_dir_create_failed": "Unable to create cache directory {path}: {error}",
        "cache_dir_check_failed": "Unable to inspect cache directory {path}: {error}",
        "cache_dir_unsafe": "Cache directory is unsafe: {path}",
        "cache_dir_wrong_owner": (
            "Cache directory is not owned by the current user: {path}"
        ),
        "cache_dir_permissions": (
            "Unsafe cache directory permissions for {path}: {mode:04o}; 0700 required"
        ),
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
        "base_url_scheme": "Base URL must use https:// or local http://",
        "base_url_invalid": "Base URL is invalid",
        "base_url_host": "Base URL must include a host",
        "base_url_userinfo": "Base URL cannot include credentials",
        "base_url_components": "Base URL cannot include a query or fragment",
        "base_url_https": "Base URL must use HTTPS; HTTP is allowed only on loopback",
        "status_invalid": "Invalid status. Allowed values: valid, revoked, expired, all",
        "list_format_unexpected": "HARICA returned an unexpected format while listing certificates",
        "serial_empty": "Serial number cannot be empty",
        "download_certificate_missing": (
            "The HARICA response does not contain a certificate field"
        ),
        "download_certificate_not_text": (
            "The certificate field in the HARICA response is not text"
        ),
        "download_certificate_empty": (
            "The certificate field in the HARICA response is empty"
        ),
        "download_certificate_ambiguous": (
            "The HARICA response contains multiple different certificates"
        ),
        "download_certificate_invalid": (
            "The certificate field does not contain a valid X.509 certificate"
        ),
        "download_multiple_certificates": (
            "The download contains multiple certificates or a chain; "
            "only one certificate is allowed"
        ),
        "download_private_key_rejected": (
            "The download contains a private key and cannot be saved"
        ),
        "download_format_unsupported": (
            "The certificate format is unsupported; PEM or base64 DER is required"
        ),
        "download_destination_check_failed": (
            "Unable to inspect destination {path}: {error}"
        ),
        "download_destination_symlink": (
            "The destination cannot be a symbolic link: {path}"
        ),
        "download_destination_not_regular": (
            "The existing destination is not a regular file: {path}"
        ),
        "download_destination_exists": (
            "The destination file already exists: {path}. Use --force to overwrite it"
        ),
        "download_directory_create_failed": (
            "Unable to create destination directory {path}: {error}"
        ),
        "download_directory_not_directory": (
            "The destination path is not a directory: {path}"
        ),
        "download_write_failed": (
            "Unable to write the certificate to {path}: {error}"
        ),
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
        "windows_config_absolute": (
            "APPDATA must be a local absolute Windows path"
        ),
        "env_empty": "{name} is set but empty",
        "default_file": "default file",
        "configuration": "configuration",
        "environment_variable_set": "environment variable is set",
        "secure_file_detail": "regular file, correct owner, and secure permissions",
        "dpapi_file_detail": (
            "file encrypted and authenticated with DPAPI for the current Windows user"
        ),
        "api_key_read_failed": "Unable to read API key file {path}: {error}",
        "api_key_file_empty": "API key file is empty: {path}",
        "api_key_empty": "API key cannot be empty",
        "api_key_write_failed": "Unable to write API key file {path}: {error}",
        "api_key_delete_failed": "Unable to delete API key file {path}: {error}",
        "api_key_file_missing": "API key file not found: {path}",
        "api_key_file_check_failed": "Unable to inspect API key file {path}: {error}",
        "api_key_symlink": "API key file cannot be a symbolic link: {path}",
        "api_key_reparse": (
            "API key file cannot be a link, junction, or reparse point: {path}"
        ),
        "api_key_changed_during_read": (
            "API key file changed while being read: {path}"
        ),
        "dpapi_api_key_invalid_format": (
            "API key file is not a valid DPAPI container: {path}. "
            "Create it with 'harica-client auth set' or use HARICA_API_KEY "
            "for ephemeral automation"
        ),
        "dpapi_cache_invalid_format": (
            "Cache file is not a valid DPAPI container: {path}; "
            "recreate it with 'harica-client cache refresh'"
        ),
        "dpapi_protect_failed": (
            "Windows could not protect file {path} with DPAPI: {error}"
        ),
        "dpapi_unprotect_failed": (
            "Windows could not decrypt DPAPI file {path}: {error}. "
            "The file may be tampered with or belong to another user or computer"
        ),
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
    """Restituisce il percorso nativo della preferenza persistente."""
    current = os.environ if environ is None else environ
    try:
        root = config_root(current)
    except StoragePathError as exc:
        keys = {
            "config_root_not_absolute": (
                "windows_config_absolute" if IS_WINDOWS else "absolute_xdg"
            ),
            "home_not_absolute": "absolute_home",
        }
        raise LanguageSelectionError(
            keys.get(exc.reason, "windows_config_absolute")
        ) from exc
    path = root / "harica-client" / "language"
    try:
        return storage_path(path)
    except StoragePathError as exc:
        raise LanguageSelectionError(
            "language_file_not_regular",
            value=str(exc.path),
        ) from exc


def read_saved_language(
    *,
    environ: Mapping[str, str] | None = None,
) -> LanguagePreference | None:
    """Legge la preferenza persistente dopo controlli di sicurezza di base."""
    path = default_language_path(environ=environ)
    metadata = _validate_saved_language_metadata(path, missing_ok=True)
    if metadata is None:
        return None
    try:
        selected = read_stable_bytes(path, metadata).decode("utf-8").strip()
    except (OSError, UnicodeError, StoragePathError) as exc:
        raise _language_io_error(path, exc) from exc
    if selected not in SUPPORTED_LANGUAGES:
        raise LanguageSelectionError("language_invalid", value=selected)
    return LanguagePreference(selected, "saved", path)


def _validate_saved_language_metadata(
    path: Path,
    *,
    missing_ok: bool,
) -> os.stat_result | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise LanguageSelectionError("language_file_missing", value=str(path)) from None
    except OSError as exc:
        raise _language_io_error(path, exc) from exc

    if is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise LanguageSelectionError("language_file_not_regular", value=str(path))
    if not IS_WINDOWS and metadata.st_uid != os.geteuid():
        raise LanguageSelectionError("language_file_wrong_owner", value=str(path))
    if not IS_WINDOWS and metadata.st_mode & 0o022:
        raise LanguageSelectionError("language_file_writable", value=str(path))
    return metadata


def write_saved_language(
    language: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Salva atomicamente una preferenza con protezioni native della piattaforma."""
    if language not in SUPPORTED_LANGUAGES:
        raise LanguageSelectionError("language_invalid", value=language)
    path = default_language_path(environ=environ)
    directory = path.parent
    try:
        ensure_private_directory(directory)
    except (OSError, StoragePathError) as exc:
        raise _language_io_error(directory, exc) from exc
    if path.exists() or path.is_symlink():
        _validate_saved_language_metadata(path, missing_ok=False)

    try:
        atomic_write_bytes(path, f"{language}\n".encode())
    except OSError as exc:
        raise _language_io_error(path, exc) from exc
    return path


def delete_saved_language(
    *,
    environ: Mapping[str, str] | None = None,
) -> Path | None:
    """Rimuove la preferenza salvata; l'operazione è idempotente."""
    path = default_language_path(environ=environ)
    if _validate_saved_language_metadata(path, missing_ok=True) is None:
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


def _language_io_error(path: Path, error: Exception) -> LanguageSelectionError:
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
