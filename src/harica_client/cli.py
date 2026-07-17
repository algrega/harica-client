"""Interfaccia a riga di comando di harica-client."""

from __future__ import annotations

import argparse
import csv
import getpass
import hmac
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .client import Environment, HaricaClient, RetryPolicy
from .credentials import (
    credential_deletion_target,
    credential_destination,
    delete_api_key_file,
    inspect_credential,
    migrate_legacy_api_key,
    resolve_api_key,
    write_api_key_file,
)
from .errors import (
    HaricaConfigurationError,
    HaricaError,
    HaricaRateLimitError,
    HaricaResponseError,
)

_FQDN_FIELDS = frozenset(
    {
        "fqdn",
        "commonname",
        "dnsname",
        "dnsnames",
        "subjectalternativename",
        "subjectalternativenames",
        "san",
        "sans",
        "dn",
        "distinguishedname",
        "subject",
        "subjectdn",
        "friendlyname",
    }
)
_FRIENDLY_NAME_FIELDS = frozenset({"friendlyname"})
_EMAIL_FIELDS = frozenset(
    {
        "email",
        "emailaddress",
        "useremail",
        "useremailaddress",
    }
)


def _add_connection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--environment",
        choices=[item.value for item in Environment],
        default=Environment.PRODUCTION.value,
        help="Ambiente HARICA (default: production)",
    )
    parser.add_argument(
        "--base-url",
        help="Base URL personalizzata, utile per test locali (sovrascrive --environment)",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="Timeout HTTP in secondi")
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=4,
        help="Numero totale massimo di tentativi (default: 4)",
    )
    parser.add_argument(
        "--api-key-file",
        metavar="PATH",
        type=Path,
        help="File API key protetto; precede variabili d'ambiente e percorso predefinito",
    )


def _add_auth_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--environment",
        choices=[item.value for item in Environment],
        default=Environment.PRODUCTION.value,
        help="Ambiente HARICA (default: production)",
    )
    parser.add_argument(
        "--api-key-file",
        metavar="PATH",
        type=Path,
        help="Percorso alternativo del file API key",
    )


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="Stampa il JSON integrale")
    output.add_argument(
        "--csv",
        metavar="FILE",
        type=Path,
        help="Esporta tutti i campi in un file CSV UTF-8",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Sovrascrive il file indicato con --csv, se esiste",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harica-client",
        description="Client prudente per le API Certificate Manager di HARICA",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser("version", help="Mostra la versione")
    version_parser.set_defaults(handler=_run_version)

    list_parser = subparsers.add_parser("list", help="Elenca certificati per stato")
    list_parser.add_argument(
        "--status",
        choices=("valid", "revoked", "expired", "all"),
        default="valid",
        help="Stato dei certificati; all interroga i tre stati (default: valid)",
    )
    list_parser.add_argument(
        "--fqdn",
        metavar="VALUE",
        help="Filtra per FQDN, CN, SAN o DN (ricerca parziale case-insensitive)",
    )
    list_parser.add_argument(
        "--friendly-name",
        "--friendlyName",
        dest="friendly_name",
        metavar="VALUE",
        help="Filtra per friendlyName (ricerca parziale case-insensitive)",
    )
    list_parser.add_argument(
        "--email",
        metavar="VALUE",
        help="Filtra per indirizzo email (ricerca parziale case-insensitive)",
    )
    _add_output_arguments(list_parser)
    _add_connection_arguments(list_parser)
    list_parser.set_defaults(handler=_run_list)

    serial_parser = subparsers.add_parser("serial", help="Cerca un certificato per seriale")
    serial_parser.add_argument("serial_number", help="Numero seriale del certificato")
    _add_output_arguments(serial_parser)
    _add_connection_arguments(serial_parser)
    serial_parser.set_defaults(handler=_run_serial)

    auth_parser = subparsers.add_parser("auth", help="Gestisce l'API key su filesystem")
    auth_subparsers = auth_parser.add_subparsers(dest="auth_command", required=True)

    auth_set_parser = auth_subparsers.add_parser("set", help="Salva o ruota una API key")
    _add_auth_arguments(auth_set_parser)
    auth_set_parser.set_defaults(handler=_run_auth_set)

    auth_status_parser = auth_subparsers.add_parser(
        "status", help="Controlla origine e sicurezza della API key"
    )
    _add_auth_arguments(auth_status_parser)
    auth_status_parser.set_defaults(handler=_run_auth_status)

    auth_delete_parser = auth_subparsers.add_parser("delete", help="Elimina una API key")
    _add_auth_arguments(auth_delete_parser)
    auth_delete_parser.add_argument(
        "--yes",
        action="store_true",
        help="Conferma la cancellazione senza prompt interattivo",
    )
    auth_delete_parser.set_defaults(handler=_run_auth_delete)

    auth_migrate_parser = auth_subparsers.add_parser(
        "migrate", help="Migra una API key dal vecchio percorso harica-safe"
    )
    auth_migrate_parser.add_argument(
        "--environment",
        choices=[item.value for item in Environment],
        default=Environment.PRODUCTION.value,
        help="Ambiente HARICA (default: production)",
    )
    auth_migrate_parser.set_defaults(handler=_run_auth_migrate)

    return parser


def _client_from_args(args: argparse.Namespace) -> HaricaClient:
    credential = resolve_api_key(
        args.environment,
        explicit_path=args.api_key_file,
    )
    return HaricaClient(
        credential.api_key,
        environment=args.environment,
        base_url=args.base_url,
        timeout=args.timeout,
        retry_policy=RetryPolicy(max_attempts=args.max_attempts),
    )


def _run_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return 0


def _run_list(args: argparse.Namespace) -> int:
    data = _client_from_args(args).list_certificates(args.status)
    data = _filter_certificates(
        data,
        fqdn=args.fqdn,
        friendly_name=args.friendly_name,
        email=args.email,
    )
    _render_or_export(data, args)
    return 0


def _run_serial(args: argparse.Namespace) -> int:
    data = _client_from_args(args).certificate_by_serial(args.serial_number)
    _render_or_export(data, args)
    return 0


def _run_auth_set(args: argparse.Namespace) -> int:
    target = credential_destination(
        args.environment,
        explicit_path=args.api_key_file,
    )
    first = getpass.getpass("API key HARICA: ")
    second = getpass.getpass("Ripetere API key HARICA: ")
    if not hmac.compare_digest(first, second):
        raise HaricaConfigurationError("Le API key inserite non coincidono")
    written = write_api_key_file(target, first)
    print(f"API key salvata per {args.environment} in {written}")
    return 0


def _run_auth_status(args: argparse.Namespace) -> int:
    status = inspect_credential(
        args.environment,
        explicit_path=args.api_key_file,
    )
    print(f"Stato: {'valida' if status.valid else 'non valida'}")
    print(f"Origine: {status.source}")
    if status.path is not None:
        print(f"Percorso: {status.path}")
        print(f"Permessi: {'validi' if status.valid else 'da correggere'}")
    else:
        print("Percorso: non applicabile")
        print("Permessi: non applicabile")
    print(f"Dettaglio: {status.detail}")
    return 0 if status.valid else 1


def _run_auth_delete(args: argparse.Namespace) -> int:
    target = credential_deletion_target(
        args.environment,
        explicit_path=args.api_key_file,
    )
    if not args.yes:
        try:
            answer = input(f"Eliminare la API key per {args.environment} da {target}? [s/N] ")
        except EOFError as exc:
            raise HaricaConfigurationError(
                "Conferma interattiva non disponibile; usare --yes"
            ) from exc
        if answer.strip().casefold() not in {"s", "si", "sì", "y", "yes"}:
            print("Operazione annullata.")
            return 0
    deleted = delete_api_key_file(target)
    print(f"API key eliminata per {args.environment} da {deleted}")
    return 0


def _run_auth_migrate(args: argparse.Namespace) -> int:
    source, destination = migrate_legacy_api_key(args.environment)
    print(f"API key migrata per {args.environment} da {source} a {destination}")
    return 0


def _render_or_export(data: Any, args: argparse.Namespace) -> None:
    data = _without_certificate(data)
    data = _with_common_name(data)
    if args.csv is not None:
        row_count = _write_csv(data, args.csv, force=args.force)
        print(f"Esportate {row_count} righe in {args.csv.expanduser().resolve()}")
        return
    _print_data(data, force_json=args.json)


def _without_certificate(value: Any) -> Any:
    """Rimuove solo i campi chiamati esattamente 'certificate' dall'output CLI."""
    if isinstance(value, Mapping):
        return {
            key: _without_certificate(item)
            for key, item in value.items()
            if not (isinstance(key, str) and key.casefold() == "certificate")
        }
    if isinstance(value, list):
        return [_without_certificate(item) for item in value]
    return value


def _with_common_name(data: Any) -> Any:
    """Aggiunge il campo CN alle righe certificate senza mutare la risposta originale."""
    def enrich(row: Any) -> Any:
        if not isinstance(row, Mapping):
            return row
        enriched = dict(row)
        enriched["CN"] = _common_name(row)
        return enriched

    if isinstance(data, list):
        return [enrich(row) for row in data]
    if isinstance(data, Mapping):
        for key in ("certificates", "items", "results", "data"):
            candidate = data.get(key)
            if isinstance(candidate, list):
                enriched = dict(data)
                enriched[key] = [enrich(row) for row in candidate]
                return enriched
        return enrich(data)
    return data


def _filter_certificates(
    data: Any,
    *,
    fqdn: str | None = None,
    friendly_name: str | None = None,
    email: str | None = None,
) -> Any:
    """Filtra localmente gli elementi, preservando l'eventuale wrapper HARICA."""
    fqdn_filter = _normalized_filter(fqdn, option="--fqdn")
    friendly_filter = _normalized_filter(
        friendly_name,
        option="--friendly-name",
    )
    email_filter = _normalized_filter(email, option="--email")
    if fqdn_filter is None and friendly_filter is None and email_filter is None:
        return data

    def matches(row: Any) -> bool:
        if not isinstance(row, Mapping):
            return False
        if fqdn_filter is not None and not _row_matches(
            row,
            field_names=_FQDN_FIELDS,
            expected=fqdn_filter,
        ):
            return False
        if friendly_filter is not None and not _row_matches(
            row,
            field_names=_FRIENDLY_NAME_FIELDS,
            expected=friendly_filter,
        ):
            return False
        if email_filter is not None and not _row_matches(
            row,
            field_names=_EMAIL_FIELDS,
            expected=email_filter,
        ):
            return False
        return True

    if isinstance(data, list):
        return [row for row in data if matches(row)]
    if isinstance(data, Mapping):
        for key in ("certificates", "items", "results", "data"):
            candidate = data.get(key)
            if isinstance(candidate, list):
                filtered_rows = [row for row in candidate if matches(row)]
                filtered = dict(data)
                filtered[key] = filtered_rows
                for count_key in ("total", "count", "totalCount"):
                    if isinstance(filtered.get(count_key), int):
                        filtered[count_key] = len(filtered_rows)
                return filtered
        return data if matches(data) else []
    return []


def _normalized_filter(value: str | None, *, option: str) -> str | None:
    if value is None:
        return None
    normalized = value.strip().casefold()
    if not normalized:
        raise HaricaConfigurationError(f"{option} non può essere vuoto")
    return normalized


def _row_matches(
    row: Mapping[str, Any],
    *,
    field_names: frozenset[str],
    expected: str,
) -> bool:
    for key, value in row.items():
        if _normalized_field_name(key) not in field_names:
            continue
        if any(expected in candidate.casefold() for candidate in _text_values(value)):
            return True
    return False


def _normalized_field_name(value: Any) -> str:
    return "".join(character for character in str(value).casefold() if character.isalnum())


def _text_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        values: list[str] = []
        for nested in value.values():
            values.extend(_text_values(nested))
        return values
    if isinstance(value, (list, tuple, set)):
        values = []
        for nested in value:
            values.extend(_text_values(nested))
        return values
    return [str(value)]


def _print_data(data: Any, *, force_json: bool) -> None:
    if force_json:
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
        return
    rows = _extract_rows(data)
    if not rows:
        print("Nessun risultato.")
        return
    if not all(isinstance(row, Mapping) for row in rows):
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
        return
    _print_table(rows)


def _extract_rows(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, Mapping):
        for key in ("certificates", "items", "results", "data"):
            candidate = data.get(key)
            if isinstance(candidate, list):
                return candidate
        return [data]
    return [data]


def _write_csv(data: Any, destination: Path, *, force: bool = False) -> int:
    rows = _extract_rows(data)
    if not all(isinstance(row, Mapping) for row in rows):
        raise HaricaConfigurationError(
            "La risposta HARICA non è convertibile in righe CSV; usare --json"
        )

    target = destination.expanduser().resolve()
    if target.exists() and not force:
        raise HaricaConfigurationError(
            f"Il file CSV esiste già: {target}. Usare --force per sovrascriverlo"
        )
    fieldnames = _csv_fieldnames(rows)
    temporary_path: Path | None = None

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8-sig",
            newline="",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            if fieldnames:
                writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow(
                        {field: _csv_cell(row.get(field)) for field in fieldnames}
                    )
        os.replace(temporary_path, target)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise HaricaConfigurationError(f"Impossibile scrivere il CSV {target}: {exc}") from exc

    return len(rows)


def _csv_fieldnames(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    fields: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for field in row:
            name = str(field)
            if name not in seen:
                seen.add(name)
                fields.append(name)
    return fields


def _csv_cell(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        text = value if isinstance(value, (int, float)) else str(value)
    if isinstance(text, str) and text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{text}"
    return text


def _print_table(rows: Sequence[Mapping[str, Any]]) -> None:
    display_rows = [_with_common_name(row) for row in rows]

    preferred = (
        "serialNumber",
        "serial",
        "friendlyName",
        "CN",
        "status",
        "validFrom",
        "validTo",
        "transactionId",
        "userEmail",
        "email",
    )
    available = {
        key for row in display_rows for key, value in row.items() if _is_scalar(value)
    }
    columns = [key for key in preferred if key in available]
    if not columns:
        columns = sorted(available)[:7]
    if not columns:
        print(json.dumps(list(rows), ensure_ascii=False, indent=2, sort_keys=True))
        return

    rendered = [[_cell(row.get(column)) for column in columns] for row in display_rows]
    widths = [
        min(48, max(len(column), *(len(row[index]) for row in rendered)))
        for index, column in enumerate(columns)
    ]
    print("  ".join(column.ljust(widths[index]) for index, column in enumerate(columns)))
    print("  ".join("-" * width for width in widths))
    for row in rendered:
        print(
            "  ".join(
                row[index][: widths[index]].ljust(widths[index])
                for index in range(len(columns))
            )
        )


def _common_name(row: Mapping[str, Any]) -> str:
    """Restituisce il CN esplicito oppure lo estrae dal distinguished name."""
    for key, value in row.items():
        if _normalized_field_name(key) in {"cn", "commonname"} and _is_scalar(value):
            common_name = _cell(value).strip()
            if common_name:
                return common_name

    for key, value in row.items():
        if _normalized_field_name(key) not in {
            "dn",
            "distinguishedname",
            "subject",
            "subjectdn",
        }:
            continue
        if not isinstance(value, str):
            continue
        for component in _split_dn_components(value):
            attribute, separator, attribute_value = component.partition("=")
            if separator and _normalized_field_name(attribute) == "cn":
                return _unescape_dn_value(attribute_value.strip())
    return ""


def _split_dn_components(distinguished_name: str) -> list[str]:
    """Divide un DN su separatori non protetti da backslash."""
    components: list[str] = []
    current: list[str] = []
    escaped = False
    for character in distinguished_name:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character in {",", "+", ";"}:
            components.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    components.append("".join(current).strip())
    return components


def _unescape_dn_value(value: str) -> str:
    """Decodifica gli escape testuali ed esadecimali più comuni dei DN RFC 4514."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]

    result: list[str] = []
    index = 0
    hexadecimal = frozenset("0123456789abcdefABCDEF")
    while index < len(value):
        if value[index] != "\\" or index + 1 >= len(value):
            result.append(value[index])
            index += 1
            continue

        if (
            index + 2 < len(value)
            and value[index + 1] in hexadecimal
            and value[index + 2] in hexadecimal
        ):
            encoded = bytearray()
            while (
                index + 2 < len(value)
                and value[index] == "\\"
                and value[index + 1] in hexadecimal
                and value[index + 2] in hexadecimal
            ):
                encoded.append(int(value[index + 1 : index + 3], 16))
                index += 3
            result.append(encoded.decode("utf-8", errors="replace"))
            continue

        result.append(value[index + 1])
        index += 2
    return "".join(result)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).replace("\n", " ")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except HaricaRateLimitError as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 75
    except HaricaResponseError as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        if exc.body_preview:
            print(f"Anteprima risposta: {exc.body_preview!r}", file=sys.stderr)
        return 1
    except HaricaError as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Errore di configurazione: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
