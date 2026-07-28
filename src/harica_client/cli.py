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
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .cache import (
    CacheSnapshot,
    cache_age_hours,
    delete_cache,
    read_cache,
    resolve_cache_path,
    write_cache,
)
from .certificate_download import (
    automatic_download_destination,
    certificate_summary_from_pem,
    extract_certificate_pem,
    validate_download_destination,
    write_certificate_pem,
)
from .certificate_stats import (
    expirations_report,
    owners_report,
    quality_report,
    summary_report,
    summary_rows,
)
from .client import Environment, HaricaClient, RetryPolicy
from .credentials import (
    credential_deletion_target,
    credential_destination,
    delete_api_key_file,
    inspect_credential,
    resolve_api_key,
    write_api_key_file,
)
from .errors import (
    HaricaConfigurationError,
    HaricaError,
    HaricaRateLimitError,
    HaricaResponseError,
)
from .i18n import (
    SUPPORTED_LANGUAGES,
    LanguageSelectionError,
    delete_saved_language,
    default_language_path,
    localize_argparse_error,
    resolve_language_preference,
    tr,
    using_language,
    write_saved_language,
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
_SUMMARY_METRIC_LABELS = {
    "cache.createdAt": "stats_metric_cache_created_at",
    "cache.ageHours": "stats_metric_cache_age",
    "cache.environment": "stats_metric_cache_environment",
    "cache.baseUrl": "stats_metric_cache_source",
    "total": "stats_metric_total",
    "status.valid": "stats_metric_valid",
    "status.revoked": "stats_metric_revoked",
    "status.expired": "stats_metric_expired",
    "status.unknown": "stats_metric_unknown",
    "expiry.days0To7": "stats_metric_expiry_0_7",
    "expiry.days8To30": "stats_metric_expiry_8_30",
    "expiry.days31To60": "stats_metric_expiry_31_60",
    "expiry.days61To90": "stats_metric_expiry_61_90",
    "expiry.over90Days": "stats_metric_expiry_over_90",
    "revokedLast30Days": "stats_metric_revoked_30",
    "missingUser": "stats_metric_missing_user",
    "missingUserEmail": "stats_metric_missing_email",
    "missingCN": "stats_metric_missing_cn",
    "invalidDates": "stats_metric_invalid_dates",
}
_STATS_COLUMN_LABELS = {
    "metric": "stats_column_metric",
    "value": "stats_column_value",
    "serial": "stats_column_serial",
    "CN": "stats_column_cn",
    "friendlyName": "stats_column_friendly_name",
    "userEmail": "stats_column_email",
    "user": "stats_column_user",
    "validTo": "stats_column_valid_to",
    "daysRemaining": "stats_column_days_remaining",
    "total": "stats_column_total",
    "valid": "stats_column_valid",
    "revoked": "stats_column_revoked",
    "expired": "stats_column_expired",
    "unknown": "stats_column_unknown",
    "expiringWithin30Days": "stats_column_expiring_30",
    "issue": "stats_column_issue",
}


def _terminal_text(value: Any) -> str:
    """Rende inerti e visibili i controlli in testo destinato al terminale."""
    rendered: list[str] = []
    for character in str(value):
        codepoint = ord(character)
        category = unicodedata.category(character)

        if character in {"\n", "\r", "\t"}:
            rendered.append(" ")
        elif category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            if codepoint <= 0xFF:
                rendered.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                rendered.append(f"\\u{codepoint:04x}")
            else:
                rendered.append(f"\\U{codepoint:08x}")
        else:
            rendered.append(character)
    return "".join(rendered)


def _print_terminal(value: Any, *, file: Any = None) -> None:
    """Stampa una singola riga dopo la sanitizzazione del contenuto dinamico."""
    print(_terminal_text(value), file=file)


class LocalizedArgumentParser(argparse.ArgumentParser):
    """ArgumentParser con help ed errori controllati dalla lingua della CLI."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["add_help"] = False
        if sys.version_info >= (3, 14):
            kwargs["color"] = False
        super().__init__(*args, **kwargs)
        self._positionals.title = tr("positional_arguments")
        self._optionals.title = tr("options")
        self.add_argument("-h", "--help", action="help", help=tr("show_help"))

    def format_usage(self) -> str:
        return super().format_usage().replace("usage: ", f"{tr('usage')}: ", 1)

    def format_help(self) -> str:
        return super().format_help().replace("usage: ", f"{tr('usage')}: ", 1)

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        rendered = _terminal_text(
            f"{self.prog}: {tr('error').casefold()}: "
            f"{localize_argparse_error(message)}"
        )
        self.exit(
            2,
            f"{rendered}\n",
        )


def _add_language_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--language",
        choices=SUPPORTED_LANGUAGES,
        default=argparse.SUPPRESS,
        help=tr("help_language"),
    )


def _add_connection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--environment",
        choices=[item.value for item in Environment],
        default=Environment.PRODUCTION.value,
        help=tr("help_environment"),
    )
    parser.add_argument(
        "--base-url",
        help=tr("help_base_url"),
    )
    parser.add_argument("--timeout", type=float, default=30.0, help=tr("help_timeout"))
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=4,
        help=tr("help_max_attempts"),
    )
    parser.add_argument(
        "--api-key-file",
        metavar="PATH",
        type=Path,
        help=tr("help_api_key_file"),
    )


def _add_auth_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--environment",
        choices=[item.value for item in Environment],
        default=Environment.PRODUCTION.value,
        help=tr("help_environment"),
    )
    parser.add_argument(
        "--api-key-file",
        metavar="PATH",
        type=Path,
        help=tr("help_auth_api_key_file"),
    )


def _add_output_arguments(
    parser: argparse.ArgumentParser,
    *,
    json_help_key: str = "help_json",
) -> None:
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help=tr(json_help_key))
    output.add_argument(
        "--csv",
        metavar="FILE",
        type=Path,
        help=tr("help_csv"),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=tr("help_force"),
    )


def _add_cache_location_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--environment",
        choices=[item.value for item in Environment],
        default=Environment.PRODUCTION.value,
        help=tr("help_environment"),
    )
    parser.add_argument(
        "--cache-file",
        metavar="PATH",
        type=Path,
        help=tr("help_cache_file"),
    )


def _add_stats_arguments(parser: argparse.ArgumentParser) -> None:
    _add_cache_location_arguments(parser)
    parser.add_argument(
        "--max-cache-age",
        metavar="HOURS",
        type=float,
        help=tr("help_max_cache_age"),
    )
    _add_output_arguments(parser, json_help_key="help_stats_json")


def build_parser() -> argparse.ArgumentParser:
    parser = LocalizedArgumentParser(
        prog="harica-client",
        description=tr("app_description"),
    )
    _add_language_argument(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser("version", help=tr("help_version"))
    _add_language_argument(version_parser)
    version_parser.set_defaults(handler=_run_version)

    language_parser = subparsers.add_parser(
        "language",
        help=tr("help_language_command"),
    )
    _add_language_argument(language_parser)
    language_subparsers = language_parser.add_subparsers(
        dest="language_command",
        required=True,
    )

    language_set_parser = language_subparsers.add_parser(
        "set",
        help=tr("help_language_set"),
    )
    _add_language_argument(language_set_parser)
    language_set_parser.add_argument(
        "language_value",
        choices=SUPPORTED_LANGUAGES,
        help=tr("language_value"),
    )
    language_set_parser.set_defaults(handler=_run_language_set)

    language_status_parser = language_subparsers.add_parser(
        "status",
        help=tr("help_language_status"),
    )
    _add_language_argument(language_status_parser)
    language_status_parser.set_defaults(handler=_run_language_status)

    language_reset_parser = language_subparsers.add_parser(
        "reset",
        help=tr("help_language_reset"),
    )
    _add_language_argument(language_reset_parser)
    language_reset_parser.set_defaults(handler=_run_language_reset)

    list_parser = subparsers.add_parser("list", help=tr("help_list"))
    _add_language_argument(list_parser)
    list_parser.add_argument(
        "--status",
        choices=("valid", "revoked", "expired", "all"),
        default="valid",
        help=tr("help_status"),
    )
    list_parser.add_argument(
        "--fqdn",
        metavar="VALUE",
        help=tr("help_fqdn"),
    )
    list_parser.add_argument(
        "--friendly-name",
        "--friendlyName",
        dest="friendly_name",
        metavar="VALUE",
        help=tr("help_friendly_name"),
    )
    list_parser.add_argument(
        "--email",
        metavar="VALUE",
        help=tr("help_email"),
    )
    list_parser.add_argument(
        "--from-cache",
        action="store_true",
        help=tr("help_from_cache"),
    )
    list_parser.add_argument(
        "--cache-file",
        metavar="PATH",
        type=Path,
        help=tr("help_cache_file"),
    )
    list_parser.add_argument(
        "--max-cache-age",
        metavar="HOURS",
        type=float,
        help=tr("help_max_cache_age"),
    )
    _add_output_arguments(list_parser)
    _add_connection_arguments(list_parser)
    list_parser.set_defaults(handler=_run_list)

    serial_parser = subparsers.add_parser("serial", help=tr("help_serial"))
    _add_language_argument(serial_parser)
    serial_parser.add_argument("serial_number", help=tr("serial_number"))
    _add_output_arguments(serial_parser)
    _add_connection_arguments(serial_parser)
    serial_parser.set_defaults(handler=_run_serial)

    download_parser = subparsers.add_parser(
        "download",
        help=tr("help_download"),
    )
    _add_language_argument(download_parser)
    download_parser.add_argument("serial_number", help=tr("serial_number"))
    download_parser.add_argument(
        "--output",
        metavar="FILE",
        type=Path,
        help=tr("help_download_output"),
    )
    download_parser.add_argument(
        "--force",
        action="store_true",
        help=tr("help_download_force"),
    )
    _add_connection_arguments(download_parser)
    download_parser.set_defaults(handler=_run_download)

    auth_parser = subparsers.add_parser("auth", help=tr("help_auth"))
    _add_language_argument(auth_parser)
    auth_subparsers = auth_parser.add_subparsers(dest="auth_command", required=True)

    auth_set_parser = auth_subparsers.add_parser("set", help=tr("help_auth_set"))
    _add_language_argument(auth_set_parser)
    _add_auth_arguments(auth_set_parser)
    auth_set_parser.set_defaults(handler=_run_auth_set)

    auth_status_parser = auth_subparsers.add_parser(
        "status", help=tr("help_auth_status")
    )
    _add_language_argument(auth_status_parser)
    _add_auth_arguments(auth_status_parser)
    auth_status_parser.set_defaults(handler=_run_auth_status)

    auth_delete_parser = auth_subparsers.add_parser("delete", help=tr("help_auth_delete"))
    _add_language_argument(auth_delete_parser)
    _add_auth_arguments(auth_delete_parser)
    auth_delete_parser.add_argument(
        "--yes",
        action="store_true",
        help=tr("help_yes"),
    )
    auth_delete_parser.set_defaults(handler=_run_auth_delete)

    cache_parser = subparsers.add_parser("cache", help=tr("help_cache"))
    _add_language_argument(cache_parser)
    cache_subparsers = cache_parser.add_subparsers(
        dest="cache_command",
        required=True,
    )

    cache_refresh_parser = cache_subparsers.add_parser(
        "refresh",
        help=tr("help_cache_refresh"),
    )
    _add_language_argument(cache_refresh_parser)
    _add_connection_arguments(cache_refresh_parser)
    cache_refresh_parser.add_argument(
        "--cache-file",
        metavar="PATH",
        type=Path,
        help=tr("help_cache_file"),
    )
    cache_refresh_parser.set_defaults(handler=_run_cache_refresh)

    cache_status_parser = cache_subparsers.add_parser(
        "status",
        help=tr("help_cache_status"),
    )
    _add_language_argument(cache_status_parser)
    _add_cache_location_arguments(cache_status_parser)
    cache_status_parser.set_defaults(handler=_run_cache_status)

    cache_delete_parser = cache_subparsers.add_parser(
        "delete",
        help=tr("help_cache_delete"),
    )
    _add_language_argument(cache_delete_parser)
    _add_cache_location_arguments(cache_delete_parser)
    cache_delete_parser.add_argument(
        "--yes",
        action="store_true",
        help=tr("help_yes"),
    )
    cache_delete_parser.set_defaults(handler=_run_cache_delete)

    stats_parser = subparsers.add_parser("stats", help=tr("help_stats"))
    _add_language_argument(stats_parser)
    stats_subparsers = stats_parser.add_subparsers(
        dest="stats_command",
        required=True,
    )

    stats_summary_parser = stats_subparsers.add_parser(
        "summary",
        help=tr("help_stats_summary"),
    )
    _add_language_argument(stats_summary_parser)
    _add_stats_arguments(stats_summary_parser)
    stats_summary_parser.set_defaults(handler=_run_stats_summary)

    stats_expirations_parser = stats_subparsers.add_parser(
        "expirations",
        help=tr("help_stats_expirations"),
    )
    _add_language_argument(stats_expirations_parser)
    _add_stats_arguments(stats_expirations_parser)
    stats_expirations_parser.add_argument(
        "--within",
        metavar="DAYS",
        type=int,
        default=30,
        help=tr("help_stats_within"),
    )
    stats_expirations_parser.set_defaults(handler=_run_stats_expirations)

    stats_owners_parser = stats_subparsers.add_parser(
        "owners",
        help=tr("help_stats_owners"),
    )
    _add_language_argument(stats_owners_parser)
    _add_stats_arguments(stats_owners_parser)
    stats_owners_parser.set_defaults(handler=_run_stats_owners)

    stats_quality_parser = stats_subparsers.add_parser(
        "quality",
        help=tr("help_stats_quality"),
    )
    _add_language_argument(stats_quality_parser)
    _add_stats_arguments(stats_quality_parser)
    stats_quality_parser.set_defaults(handler=_run_stats_quality)

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


def _run_language_set(args: argparse.Namespace) -> int:
    path = write_saved_language(args.language_value)
    with using_language(args.language_value):
        _print_terminal(tr("language_saved", language=args.language_value, path=path))
    return 0


def _run_language_status(args: argparse.Namespace) -> int:
    preference = args.language_preference
    source = tr(f"language_source_{preference.source}")
    _print_terminal(f"{tr('language_label')}: {preference.language}")
    _print_terminal(f"{tr('source')}: {source}")
    path = preference.path or default_language_path()
    _print_terminal(f"{tr('path')}: {path}")
    return 0


def _run_language_reset(_args: argparse.Namespace) -> int:
    path = delete_saved_language()
    if path is None:
        _print_terminal(tr("language_not_saved"))
    else:
        _print_terminal(tr("language_reset", path=path))
    return 0


def _run_list(args: argparse.Namespace) -> int:
    if not args.from_cache:
        if args.cache_file is not None:
            raise HaricaConfigurationError(tr("cache_file_requires_from_cache"))
        if args.max_cache_age is not None:
            raise HaricaConfigurationError(tr("cache_age_requires_from_cache"))
        data = _client_from_args(args).list_certificates(args.status)
    else:
        cache_path = resolve_cache_path(
            args.environment,
            explicit_path=args.cache_file,
        )
        snapshot = read_cache(
            cache_path,
            expected_environment=args.environment,
            max_age_hours=args.max_cache_age,
        )
        data = _filter_certificates_by_status(snapshot.certificates, args.status)
    data = _filter_certificates(
        data,
        fqdn=args.fqdn,
        friendly_name=args.friendly_name,
        email=args.email,
    )
    _render_or_export(data, args)
    return 0


def _run_cache_refresh(args: argparse.Namespace) -> int:
    if args.base_url is not None and args.cache_file is None:
        raise HaricaConfigurationError(tr("cache_custom_url_requires_file"))
    client = _client_from_args(args)
    data = _without_certificate(client.list_certificates("all"))
    if not isinstance(data, list) or not all(isinstance(row, Mapping) for row in data):
        raise HaricaConfigurationError(tr("cache_response_invalid"))
    target = resolve_cache_path(
        args.environment,
        explicit_path=args.cache_file,
    )
    snapshot = write_cache(
        target,
        environment=args.environment,
        base_url=client.base_url,
        certificates=data,
    )
    _print_terminal(
        tr(
            "cache_saved",
            environment=args.environment,
            count=len(snapshot.certificates),
            path=target,
        )
    )
    return 0


def _run_cache_status(args: argparse.Namespace) -> int:
    target = resolve_cache_path(
        args.environment,
        explicit_path=args.cache_file,
    )
    try:
        snapshot = read_cache(target, expected_environment=args.environment)
    except HaricaConfigurationError as exc:
        _print_terminal(f"{tr('status')}: {tr('invalid')}")
        _print_terminal(f"{tr('path')}: {target}")
        _print_terminal(f"{tr('detail')}: {exc}")
        return 1
    _print_terminal(f"{tr('status')}: {tr('valid')}")
    _print_terminal(f"{tr('path')}: {target}")
    _print_terminal(f"{tr('cache_environment')}: {snapshot.environment}")
    _print_terminal(f"{tr('cache_base_url')}: {snapshot.base_url}")
    created_at = snapshot.created_at.isoformat().replace("+00:00", "Z")
    _print_terminal(f"{tr('cache_created_at')}: {created_at}")
    _print_terminal(f"{tr('cache_age_hours')}: {cache_age_hours(snapshot):.2f}")
    _print_terminal(f"{tr('cache_certificates')}: {len(snapshot.certificates)}")
    return 0


def _run_cache_delete(args: argparse.Namespace) -> int:
    target = resolve_cache_path(
        args.environment,
        explicit_path=args.cache_file,
    )
    if not args.yes:
        try:
            answer = input(
                _terminal_text(
                    tr(
                        "cache_delete_prompt",
                        environment=args.environment,
                        path=target,
                    )
                )
            )
        except EOFError as exc:
            raise HaricaConfigurationError(tr("confirmation_unavailable")) from exc
        if answer.strip().casefold() not in {"s", "si", "sì", "y", "yes"}:
            _print_terminal(tr("operation_cancelled"))
            return 0
    deleted = delete_cache(target)
    _print_terminal(
        tr("cache_deleted", environment=args.environment, path=deleted)
    )
    return 0


def _stats_snapshot(args: argparse.Namespace) -> CacheSnapshot:
    target = resolve_cache_path(
        args.environment,
        explicit_path=args.cache_file,
    )
    return read_cache(
        target,
        expected_environment=args.environment,
        max_age_hours=args.max_cache_age,
    )


def _run_stats_summary(args: argparse.Namespace) -> int:
    report = summary_report(_stats_snapshot(args))
    rows = summary_rows(report)
    display_rows = [
        {
            "metric": tr(_SUMMARY_METRIC_LABELS[row["metric"]]),
            "value": row["value"],
        }
        for row in rows
    ]
    _render_stats(
        args,
        json_data=report,
        csv_rows=rows,
        table_rows=display_rows,
        columns=("metric", "value"),
    )
    return 0


def _run_stats_expirations(args: argparse.Namespace) -> int:
    if args.within <= 0:
        raise HaricaConfigurationError(tr("stats_within_positive"))
    snapshot = _stats_snapshot(args)
    report = expirations_report(
        snapshot.certificates,
        within_days=args.within,
    )
    rows = report["certificates"]
    _render_stats(
        args,
        json_data=report,
        csv_rows=rows,
        table_rows=rows,
        columns=(
            "serial",
            "CN",
            "friendlyName",
            "userEmail",
            "validTo",
            "daysRemaining",
        ),
    )
    skipped = report["skippedInvalidDates"]
    if skipped:
        _print_terminal(
            tr("stats_expirations_skipped", count=skipped),
            file=sys.stderr,
        )
    return 0


def _run_stats_owners(args: argparse.Namespace) -> int:
    rows = owners_report(_stats_snapshot(args).certificates)
    display_rows = [
        {
            **row,
            "userEmail": row["userEmail"] or tr("stats_missing_owner"),
            "user": row["user"] or tr("stats_missing_owner"),
        }
        for row in rows
    ]
    _render_stats(
        args,
        json_data=rows,
        csv_rows=rows,
        table_rows=display_rows,
        columns=(
            "userEmail",
            "user",
            "total",
            "valid",
            "revoked",
            "expired",
            "unknown",
            "expiringWithin30Days",
        ),
    )
    return 0


def _run_stats_quality(args: argparse.Namespace) -> int:
    rows = quality_report(_stats_snapshot(args).certificates)
    _render_stats(
        args,
        json_data=rows,
        csv_rows=rows,
        table_rows=rows,
        columns=("serial", "CN", "friendlyName", "issue"),
    )
    return 0


def _render_stats(
    args: argparse.Namespace,
    *,
    json_data: Any,
    csv_rows: Sequence[Mapping[str, Any]],
    table_rows: Sequence[Mapping[str, Any]],
    columns: Sequence[str],
) -> None:
    if args.csv is not None:
        row_count = _write_csv(
            csv_rows,
            args.csv,
            force=args.force,
            fieldnames=columns,
        )
        _print_terminal(
            tr(
                "rows_exported",
                count=row_count,
                path=args.csv.expanduser().resolve(),
            )
        )
        return
    if args.json:
        print(json.dumps(json_data, ensure_ascii=False, indent=2, sort_keys=True))
        return
    _print_stats_table(table_rows, columns)


def _run_serial(args: argparse.Namespace) -> int:
    data = _client_from_args(args).certificate_by_serial(args.serial_number)
    _render_or_export(data, args)
    return 0


def _run_download(args: argparse.Namespace) -> int:
    target = None
    if args.output is not None:
        target = validate_download_destination(args.output, force=args.force)
    response = _client_from_args(args).certificate_by_serial(args.serial_number)
    certificate_pem = extract_certificate_pem(response)
    summary = certificate_summary_from_pem(certificate_pem)
    if target is None:
        target = automatic_download_destination(summary)
        validate_download_destination(target, force=args.force)
    written = write_certificate_pem(target, certificate_pem, force=args.force)
    _print_terminal(f"{tr('download_summary_path')}: {written}")
    _print_terminal(
        f"{tr('download_summary_serial')}: {summary.serial_number}"
    )
    _print_terminal(f"{tr('download_summary_subject')}: {summary.subject}")
    _print_terminal(f"{tr('download_summary_issuer')}: {summary.issuer}")
    _print_terminal(f"{tr('download_summary_valid_from')}: {summary.not_before}")
    _print_terminal(f"{tr('download_summary_valid_until')}: {summary.not_after}")
    return 0


def _run_auth_set(args: argparse.Namespace) -> int:
    target = credential_destination(
        args.environment,
        explicit_path=args.api_key_file,
    )
    first = getpass.getpass(tr("api_key_prompt"))
    second = getpass.getpass(tr("api_key_repeat_prompt"))
    if not hmac.compare_digest(first, second):
        raise HaricaConfigurationError(tr("api_keys_mismatch"))
    written = write_api_key_file(target, first)
    _print_terminal(tr("api_key_saved", environment=args.environment, path=written))
    return 0


def _run_auth_status(args: argparse.Namespace) -> int:
    status = inspect_credential(
        args.environment,
        explicit_path=args.api_key_file,
    )
    _print_terminal(f"{tr('status')}: {tr('valid') if status.valid else tr('invalid')}")
    _print_terminal(f"{tr('source')}: {status.source}")
    if status.path is not None:
        _print_terminal(f"{tr('path')}: {status.path}")
        _print_terminal(
            f"{tr('permissions')}: "
            f"{tr('permissions_valid') if status.valid else tr('permissions_fix')}"
        )
    else:
        _print_terminal(f"{tr('path')}: {tr('not_applicable')}")
        _print_terminal(f"{tr('permissions')}: {tr('not_applicable')}")
    _print_terminal(f"{tr('detail')}: {status.detail}")
    return 0 if status.valid else 1


def _run_auth_delete(args: argparse.Namespace) -> int:
    target = credential_deletion_target(
        args.environment,
        explicit_path=args.api_key_file,
    )
    if not args.yes:
        try:
            answer = input(
                _terminal_text(
                    tr("delete_prompt", environment=args.environment, path=target)
                )
            )
        except EOFError as exc:
            raise HaricaConfigurationError(tr("confirmation_unavailable")) from exc
        if answer.strip().casefold() not in {"s", "si", "sì", "y", "yes"}:
            _print_terminal(tr("operation_cancelled"))
            return 0
    deleted = delete_api_key_file(target)
    _print_terminal(tr("api_key_deleted", environment=args.environment, path=deleted))
    return 0


def _render_or_export(data: Any, args: argparse.Namespace) -> None:
    data = _without_certificate(data)
    data = _with_common_name(data)
    if args.csv is not None:
        row_count = _write_csv(data, args.csv, force=args.force)
        _print_terminal(
            tr(
                "rows_exported",
                count=row_count,
                path=args.csv.expanduser().resolve(),
            )
        )
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


def _filter_certificates_by_status(
    certificates: Sequence[Mapping[str, Any]],
    status: str,
) -> list[Mapping[str, Any]]:
    """Seleziona localmente uno stato dalla fotografia completa della cache."""
    if status == "all":
        return list(certificates)
    return [
        row
        for row in certificates
        if str(row.get("status", "")).strip().casefold() == status
    ]


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
        raise HaricaConfigurationError(tr("empty_filter", option=option))
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
        print(tr("no_results"))
        return
    if not all(isinstance(row, Mapping) for row in rows):
        _print_terminal(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
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


def _write_csv(
    data: Any,
    destination: Path,
    *,
    force: bool = False,
    fieldnames: Sequence[str] | None = None,
) -> int:
    rows = _extract_rows(data)
    if not all(isinstance(row, Mapping) for row in rows):
        raise HaricaConfigurationError(tr("csv_not_rows"))

    target = destination.expanduser().resolve()
    if target.exists() and not force:
        raise HaricaConfigurationError(tr("csv_exists", path=target))
    selected_fieldnames = (
        [str(field) for field in fieldnames]
        if fieldnames is not None
        else _csv_fieldnames(rows)
    )
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
            if selected_fieldnames:
                writer = csv.DictWriter(
                    stream,
                    fieldnames=selected_fieldnames,
                    extrasaction="ignore",
                )
                writer.writeheader()
                for row in rows:
                    writer.writerow(
                        {
                            field: _csv_cell(row.get(field))
                            for field in selected_fieldnames
                        }
                    )
        os.replace(temporary_path, target)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise HaricaConfigurationError(
            tr("csv_write_failed", path=target, error=exc)
        ) from exc

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
        _print_terminal(
            json.dumps(list(rows), ensure_ascii=False, indent=2, sort_keys=True)
        )
        return

    safe_columns = [_terminal_text(column) for column in columns]
    rendered = [[_cell(row.get(column)) for column in columns] for row in display_rows]
    widths = [
        min(48, max(len(column), *(len(row[index]) for row in rendered)))
        for index, column in enumerate(safe_columns)
    ]
    print(
        "  ".join(
            column.ljust(widths[index]) for index, column in enumerate(safe_columns)
        )
    )
    print("  ".join("-" * width for width in widths))
    for row in rendered:
        print(
            "  ".join(
                row[index][: widths[index]].ljust(widths[index])
                for index in range(len(columns))
            )
        )


def _print_stats_table(
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[str],
) -> None:
    if not rows:
        _print_terminal(tr("no_results"))
        return
    headers = [
        _terminal_text(tr(_STATS_COLUMN_LABELS.get(column, column)))
        for column in columns
    ]
    rendered = [[_cell(row.get(column)) for column in columns] for row in rows]
    widths = [
        min(48, max(len(header), *(len(row[index]) for row in rendered)))
        for index, header in enumerate(headers)
    ]
    print(
        "  ".join(
            header.ljust(widths[index]) for index, header in enumerate(headers)
        )
    )
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
            common_name = str(value).strip()
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
    return _terminal_text(value)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        preference = resolve_language_preference(arguments)
    except LanguageSelectionError as exc:
        with using_language(exc.fallback_language):
            parser = build_parser()
            parser.error(str(exc))

    with using_language(preference.language):
        parser = build_parser()
        args = parser.parse_args(arguments)
        args.language_preference = preference
        try:
            return int(args.handler(args))
        except HaricaRateLimitError as exc:
            _print_terminal(f"{tr('error')}: {exc}", file=sys.stderr)
            return 75
        except HaricaResponseError as exc:
            _print_terminal(f"{tr('error')}: {exc}", file=sys.stderr)
            if exc.body_preview:
                _print_terminal(
                    f"{tr('response_preview')}: {exc.body_preview!r}",
                    file=sys.stderr,
                )
            return 1
        except HaricaConfigurationError as exc:
            _print_terminal(f"{tr('configuration_error')}: {exc}", file=sys.stderr)
            return 2
        except HaricaError as exc:
            _print_terminal(f"{tr('error')}: {exc}", file=sys.stderr)
            return 1
        except ValueError as exc:
            _print_terminal(f"{tr('configuration_error')}: {exc}", file=sys.stderr)
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
