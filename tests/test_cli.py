from __future__ import annotations

import csv
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from harica_client.cache import default_cache_path, read_cache, write_cache
from harica_client.cli import (
    _client_from_args,
    _extract_rows,
    _filter_certificates,
    _filter_certificates_by_status,
    _print_table,
    _render_or_export,
    _terminal_text,
    _without_certificate,
    _write_csv,
    build_parser,
    main,
)
from harica_client.errors import (
    HaricaConfigurationError,
    HaricaError,
    HaricaRateLimitError,
)
from harica_client.credentials import write_api_key_file


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["version"])
        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue().strip(), "0.18.0")

    def test_extract_wrapped_rows(self) -> None:
        self.assertEqual(
            _extract_rows({"data": [{"serialNumber": "01"}]}),
            [{"serialNumber": "01"}],
        )

    def test_table_output(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            _print_table([{"serialNumber": "01", "commonName": "example.org"}])
        rendered = output.getvalue()
        self.assertIn("serialNumber", rendered)
        self.assertIn("CN", rendered)
        self.assertIn("example.org", rendered)

    def test_terminal_text_neutralizes_controls_and_preserves_normal_unicode(self) -> None:
        malicious = (
            "\x1b[31mRED\x1b[0m\x1b]52;c;ZmFrZQ==\x07"
            "\r\n\t\x00\u202e\u2028\ud800"
        )

        rendered = _terminal_text(malicious)

        for character in ("\x1b", "\x07", "\x00", "\u202e", "\u2028", "\ud800"):
            self.assertNotIn(character, rendered)
        self.assertIn(r"\x1b[31mRED\x1b[0m", rendered)
        self.assertIn(r"\x1b]52;c;ZmFrZQ==\x07", rendered)
        self.assertIn(r"\x00\u202e\u2028\ud800", rendered)
        self.assertIn("   ", rendered)
        self.assertEqual(_terminal_text("caffè – Αθήνα"), "caffè – Αθήνα")

    def test_table_neutralizes_terminal_sequences_in_remote_fields(self) -> None:
        malicious = "portal.example.org\x1b[2J\x1b]52;c;ZmFrZQ==\x07\u202e"
        output = io.StringIO()

        with redirect_stdout(output):
            _print_table([{"friendlyName": malicious}])

        rendered = output.getvalue()
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn(r"\x1b[2J", rendered)
        self.assertIn(r"\x1b]52;c;ZmFrZQ==\x07", rendered)

    def test_application_errors_neutralize_terminal_sequences(self) -> None:
        malicious = "remote error\x1b[2J\x07\u202e"
        output = io.StringIO()
        errors = io.StringIO()

        with (
            patch(
                "harica_client.cli._run_version",
                side_effect=HaricaConfigurationError(malicious),
            ),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            code = main(["version"])

        rendered = output.getvalue() + errors.getvalue()
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn(r"\x1b[2J\x07\u202e", rendered)

    def test_cli_exit_codes_distinguish_configuration_and_runtime_errors(self) -> None:
        cases = (
            (HaricaConfigurationError("invalid configuration"), 2),
            (HaricaError("runtime failure"), 1),
            (HaricaRateLimitError("rate limited", retry_after=None), 75),
        )
        for error, expected in cases:
            with self.subTest(error=type(error).__name__):
                with (
                    patch("harica_client.cli._run_version", side_effect=error),
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                ):
                    code = main(["version"])
                self.assertEqual(code, expected)

    def test_argparse_errors_neutralize_terminal_sequences(self) -> None:
        malicious = "valid\x1b[2J\x07\u202e"
        errors = io.StringIO()

        with (
            patch.dict(
                "os.environ",
                {
                    "FORCE_COLOR": "1",
                    "PYTHON_COLORS": "1",
                    "HARICA_CLIENT_LANGUAGE": "it",
                },
                clear=True,
            ),
            redirect_stderr(errors),
            self.assertRaises(SystemExit) as caught,
        ):
            main(["list", "--status", malicious])

        rendered = errors.getvalue()
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\u202e", rendered)

    def test_table_extracts_cn_from_dn_when_friendly_name_differs(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            _print_table(
                [
                    {
                        "serial": "01",
                        "friendlyName": "Portale produzione",
                        "dN": "C=IT,O=Example,CN=portal.example.org",
                    },
                    {
                        "serial": "02",
                        "friendlyName": "Nome con virgola",
                        "dN": r"C=IT,O=Example,CN=Example\, Production",
                    },
                ]
            )

        rendered = output.getvalue()
        self.assertIn("CN", rendered)
        self.assertIn("portal.example.org", rendered)
        self.assertIn("Example, Production", rendered)

    def test_json_export_contains_derived_cn(self) -> None:
        output = io.StringIO()
        args = SimpleNamespace(csv=None, json=True, force=False)
        with redirect_stdout(output):
            _render_or_export(
                [{"serial": "01", "dN": "C=IT,O=Example,CN=portal.example.org"}],
                args,
            )

        exported = json.loads(output.getvalue())
        self.assertEqual(exported[0]["CN"], "portal.example.org")

    def test_json_export_preserves_control_characters_as_data(self) -> None:
        value = "portal.example.org\x1b[2J\u202e"
        output = io.StringIO()
        args = SimpleNamespace(csv=None, json=True, force=False)

        with redirect_stdout(output):
            _render_or_export([{"serial": "01", "friendlyName": value}], args)

        exported = json.loads(output.getvalue())
        self.assertEqual(exported[0]["friendlyName"], value)

    def test_csv_export_contains_derived_cn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificates.csv"
            args = SimpleNamespace(csv=target, json=False, force=False)
            with redirect_stdout(io.StringIO()):
                _render_or_export(
                    [{"serial": "01", "dN": "C=IT,O=Example,CN=portal.example.org"}],
                    args,
                )
            with target.open(encoding="utf-8-sig", newline="") as stream:
                exported = next(csv.DictReader(stream))

        self.assertEqual(exported["CN"], "portal.example.org")

    def test_csv_export_preserves_control_characters_as_data(self) -> None:
        value = "portal.example.org\x1b[2J\u202e"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificates.csv"
            _write_csv([{"friendlyName": value}], target)
            with target.open(encoding="utf-8-sig", newline="") as stream:
                exported = next(csv.DictReader(stream))

        self.assertEqual(exported["friendlyName"], value)

    def test_fqdn_filter_matches_dn_san_and_friendly_name(self) -> None:
        data = [
            {
                "friendlyName": "auth.wifi.example.org",
                "dN": "C=IT,O=Example,CN=auth.wifi.example.org",
            },
            {
                "friendlyName": "certificate number two",
                "dnsNames": ["portal.example.org", "www.example.org"],
            },
            {"friendlyName": "unrelated", "fqdn": "other.example.net"},
        ]

        by_dn = _filter_certificates(data, fqdn="WIFI.EXAMPLE.ORG")
        by_san = _filter_certificates(data, fqdn="www.example.org")
        by_friendly_fallback = _filter_certificates(data, fqdn="certificate number")

        self.assertEqual(by_dn, [data[0]])
        self.assertEqual(by_san, [data[1]])
        self.assertEqual(by_friendly_fallback, [data[1]])

    def test_friendly_name_filter_is_case_insensitive(self) -> None:
        data = [
            {"friendlyName": "Production WiFi", "fqdn": "wifi.example.org"},
            {"friendlyName": "Development WiFi", "fqdn": "dev.example.org"},
        ]
        filtered = _filter_certificates(data, friendly_name="production")
        self.assertEqual(filtered, [data[0]])

    def test_email_filter_matches_supported_fields_case_insensitively(self) -> None:
        data = [
            {"userEmail": "Mario.Rossi@Example.org", "serial": "01"},
            {"email": "admin@example.net", "serial": "02"},
            {"emailAddress": "pki@example.com", "serial": "03"},
        ]

        by_user_email = _filter_certificates(data, email="rossi@example.org")
        by_email = _filter_certificates(data, email="ADMIN@EXAMPLE.NET")
        by_email_address = _filter_certificates(data, email="pki@")

        self.assertEqual(by_user_email, [data[0]])
        self.assertEqual(by_email, [data[1]])
        self.assertEqual(by_email_address, [data[2]])

    def test_combined_filters_use_and_logic_and_preserve_wrapper(self) -> None:
        data = {
            "total": 3,
            "data": [
                {"friendlyName": "Production WiFi", "fqdn": "wifi.example.org"},
                {"friendlyName": "Development WiFi", "fqdn": "wifi.example.org"},
                {"friendlyName": "Production Mail", "fqdn": "mail.example.org"},
            ],
        }
        filtered = _filter_certificates(
            data,
            fqdn="wifi.example.org",
            friendly_name="production",
        )
        self.assertEqual(filtered["total"], 1)
        self.assertEqual(filtered["data"], [data["data"][0]])

    def test_empty_filter_is_rejected(self) -> None:
        with self.assertRaises(HaricaConfigurationError):
            _filter_certificates([], fqdn="   ")

    def test_filtered_results_can_be_exported_to_csv(self) -> None:
        data = [
            {"friendlyName": "Production WiFi", "fqdn": "wifi.example.org"},
            {"friendlyName": "Production Mail", "fqdn": "mail.example.org"},
        ]
        filtered = _filter_certificates(data, fqdn="wifi.example.org")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "filtered.csv"
            count = _write_csv(filtered, target)
            with target.open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))

        self.assertEqual(count, 1)
        self.assertEqual(rows[0]["friendlyName"], "Production WiFi")

    def test_filter_options_are_available_on_list(self) -> None:
        args = build_parser().parse_args(
            [
                "list",
                "--fqdn",
                "wifi.example.org",
                "--friendlyName",
                "Production",
                "--email",
                "pki@example.org",
            ]
        )
        self.assertEqual(args.fqdn, "wifi.example.org")
        self.assertEqual(args.friendly_name, "Production")
        self.assertEqual(args.email, "pki@example.org")

    def test_all_status_is_available_on_list(self) -> None:
        args = build_parser().parse_args(["list", "--status", "all"])
        self.assertEqual(args.status, "all")

    def test_cached_status_filter_is_local_and_case_insensitive(self) -> None:
        data = [
            {"serial": "01", "status": "Valid"},
            {"serial": "02", "status": "revoked"},
            {"serial": "03", "status": "expired"},
        ]
        self.assertEqual(
            _filter_certificates_by_status(data, "valid"),
            [data[0]],
        )
        self.assertEqual(_filter_certificates_by_status(data, "all"), data)

    def test_all_list_filters_use_and_logic(self) -> None:
        data = [
            {
                "friendlyName": "Production WiFi",
                "fqdn": "wifi.example.org",
                "userEmail": "pki@example.org",
            },
            {
                "friendlyName": "Production WiFi",
                "fqdn": "wifi.example.org",
                "userEmail": "other@example.org",
            },
        ]

        filtered = _filter_certificates(
            data,
            fqdn="wifi.example.org",
            friendly_name="production",
            email="pki@example.org",
        )

        self.assertEqual(filtered, [data[0]])

    def test_empty_email_filter_is_rejected(self) -> None:
        with self.assertRaises(HaricaConfigurationError):
            _filter_certificates([], email="   ")

    def test_csv_output_contains_union_of_fields_and_nested_json(self) -> None:
        data = [
            {"serialNumber": "01", "dnsNames": ["a.example", "b.example"]},
            {"serialNumber": "02", "status": "Valid"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificates.csv"
            count = _write_csv(data, target)
            with target.open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))

        self.assertEqual(count, 2)
        self.assertEqual(list(rows[0]), ["serialNumber", "dnsNames", "status"])
        self.assertEqual(rows[0]["dnsNames"], '["a.example","b.example"]')
        self.assertEqual(rows[1]["status"], "Valid")

    def test_csv_does_not_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificates.csv"
            target.write_text("original", encoding="utf-8")
            with self.assertRaises(HaricaConfigurationError):
                _write_csv([{"serialNumber": "01"}], target)
            self.assertEqual(target.read_text(encoding="utf-8"), "original")

    def test_csv_force_overwrites_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificates.csv"
            target.write_text("original", encoding="utf-8")
            _write_csv([{"serialNumber": "01"}], target, force=True)
            content = target.read_text(encoding="utf-8-sig")
        self.assertIn("serialNumber", content)
        self.assertIn("01", content)

    def test_csv_escapes_spreadsheet_formula_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificates.csv"
            _write_csv([{"commonName": "=DANGEROUS()"}], target)
            with target.open(encoding="utf-8-sig", newline="") as stream:
                row = next(csv.DictReader(stream))
        self.assertEqual(row["commonName"], "'=DANGEROUS()")

    def test_json_and_csv_are_mutually_exclusive(self) -> None:
        parser = build_parser()
        with (
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            parser.parse_args(["list", "--json", "--csv", "out.csv"])
        self.assertEqual(caught.exception.code, 2)

    def test_certificate_field_is_removed_recursively(self) -> None:
        data = {
            "certificate": "PEM-AT-ROOT",
            "certificateType": "SSL",
            "data": [
                {
                    "serialNumber": "01",
                    "Certificate": "PEM-IN-ROW",
                    "certificateValidTo": "2027-01-01",
                }
            ],
        }

        filtered = _without_certificate(data)

        self.assertNotIn("certificate", filtered)
        self.assertNotIn("Certificate", filtered["data"][0])
        self.assertEqual(filtered["certificateType"], "SSL")
        self.assertEqual(filtered["data"][0]["certificateValidTo"], "2027-01-01")

    def test_filtered_certificate_is_not_exported_to_csv(self) -> None:
        data = _without_certificate(
            [{"serialNumber": "01", "certificate": "PEM", "status": "Valid"}]
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificates.csv"
            _write_csv(data, target)
            with target.open(encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                rows = list(reader)

        self.assertEqual(reader.fieldnames, ["serialNumber", "status"])
        self.assertEqual(rows[0], {"serialNumber": "01", "status": "Valid"})

    def test_auth_lifecycle_does_not_print_secret(self) -> None:
        secret = "super-secret-api-key"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "credentials" / "production.key"
            output = io.StringIO()
            errors = io.StringIO()
            with (
                patch.dict(
                    "os.environ",
                    {"HARICA_CLIENT_LANGUAGE": "it"},
                    clear=True,
                ),
                patch("harica_client.cli.getpass.getpass", side_effect=[secret, secret]),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                set_code = main(
                    ["auth", "set", "--environment", "production", "--api-key-file", str(target)]
                )
                status_code = main(
                    [
                        "auth",
                        "status",
                        "--environment",
                        "production",
                        "--api-key-file",
                        str(target),
                    ]
                )
                delete_code = main(
                    [
                        "auth",
                        "delete",
                        "--environment",
                        "production",
                        "--api-key-file",
                        str(target),
                        "--yes",
                    ]
                )

        combined = output.getvalue() + errors.getvalue()
        self.assertEqual((set_code, status_code, delete_code), (0, 0, 0))
        self.assertNotIn(secret, combined)
        self.assertFalse(target.exists())

    def test_auth_set_rejects_mismatched_values_without_leaking_them(self) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "credentials" / "production.key"
            with (
                patch.dict(
                    "os.environ",
                    {"HARICA_CLIENT_LANGUAGE": "it"},
                    clear=True,
                ),
                patch(
                    "harica_client.cli.getpass.getpass",
                    side_effect=["first-secret", "second-secret"],
                ),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                code = main(["auth", "set", "--api-key-file", str(target)])

        combined = output.getvalue() + errors.getvalue()
        self.assertEqual(code, 2)
        self.assertNotIn("first-secret", combined)
        self.assertNotIn("second-secret", combined)
        self.assertFalse(target.exists())

    def test_list_and_serial_load_key_file_with_clean_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "production.key"
            write_api_key_file(target, "file-secret")
            parser = build_parser()

            for command in (
                ["list", "--api-key-file", str(target)],
                ["serial", "01", "--api-key-file", str(target)],
            ):
                args = parser.parse_args(command)
                with (
                    patch.dict("os.environ", {}, clear=True),
                    patch("harica_client.cli.HaricaClient") as client_class,
                ):
                    _client_from_args(args)
                self.assertEqual(client_class.call_args.args[0], "file-secret")

    def test_auth_status_does_not_print_environment_secret(self) -> None:
        secret = "environment-secret-not-for-output"
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch.dict(
                "os.environ",
                {
                    "HARICA_API_KEY": secret,
                    "HARICA_CLIENT_LANGUAGE": "it",
                },
                clear=True,
            ),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            code = main(["auth", "status", "--environment", "production"])

        combined = output.getvalue() + errors.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("Origine: HARICA_API_KEY", combined)
        self.assertNotIn(secret, combined)

    def test_list_from_cache_filters_without_api_key_or_network(self) -> None:
        rows = [
            {
                "serial": "01",
                "status": "valid",
                "friendlyName": "Production Portal",
                "dN": "C=IT,CN=portal.example.org",
                "userEmail": "pki@example.org",
            },
            {
                "serial": "02",
                "status": "revoked",
                "friendlyName": "Old Portal",
                "dN": "C=IT,CN=old.example.org",
                "userEmail": "old@example.org",
            },
        ]
        output = io.StringIO()
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.json"
            write_cache(
                target,
                environment="production",
                base_url="https://cm.harica.gr",
                certificates=rows,
            )
            with (
                patch.dict(
                    "os.environ",
                    {"HARICA_CLIENT_LANGUAGE": "it"},
                    clear=True,
                ),
                patch(
                    "harica_client.cli._client_from_args",
                    side_effect=AssertionError("network must not be used"),
                ) as client_factory,
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                code = main(
                    [
                        "list",
                        "--from-cache",
                        "--cache-file",
                        str(target),
                        "--status",
                        "valid",
                        "--fqdn",
                        "portal.example.org",
                        "--friendly-name",
                        "production",
                        "--email",
                        "pki@example.org",
                        "--json",
                    ]
                )

        exported = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["serial"], "01")
        self.assertEqual(exported[0]["CN"], "portal.example.org")
        self.assertEqual(errors.getvalue(), "")
        client_factory.assert_not_called()

    def test_clean_cron_environment_exports_default_cache_to_csv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                **(
                    {"APPDATA": directory, "LOCALAPPDATA": directory}
                    if os.name == "nt"
                    else {"HOME": directory}
                ),
                "PATH": os.environ.get("PATH", ""),
                "HARICA_CLIENT_LANGUAGE": "en",
            }
            cache_path = default_cache_path("production", environ=environment)
            write_cache(
                cache_path,
                environment="production",
                base_url="https://cm.harica.gr",
                certificates=[
                    {
                        "serial": "01",
                        "status": "valid",
                        "dN": "C=IT,CN=cron.example.org",
                    }
                ],
            )
            csv_path = Path(directory) / "exports" / "certificates.csv"
            with (
                patch.dict("os.environ", environment, clear=True),
                patch("harica_client.cli._client_from_args") as client_factory,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                code = main(
                    [
                        "list",
                        "--from-cache",
                        "--status",
                        "valid",
                        "--csv",
                        str(csv_path),
                    ]
                )
            with csv_path.open(encoding="utf-8-sig", newline="") as stream:
                row = next(csv.DictReader(stream))

        self.assertEqual(code, 0)
        self.assertEqual(row["CN"], "cron.example.org")
        client_factory.assert_not_called()

    def test_list_cache_options_require_from_cache(self) -> None:
        for arguments in (
            ["list", "--cache-file", "/tmp/cache.json"],
            ["list", "--max-cache-age", "24"],
        ):
            with self.subTest(arguments=arguments):
                with (
                    patch(
                        "harica_client.cli._client_from_args",
                        side_effect=AssertionError("client must not be created"),
                    ),
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(main(arguments), 2)

    def test_missing_cache_never_falls_back_to_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            with (
                patch(
                    "harica_client.cli._client_from_args",
                    side_effect=AssertionError("network fallback is forbidden"),
                ) as client_factory,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                code = main(
                    ["list", "--from-cache", "--cache-file", str(missing)]
                )
        self.assertEqual(code, 2)
        client_factory.assert_not_called()

    def test_cache_refresh_saves_complete_sanitized_snapshot(self) -> None:
        secret = "api-key-must-not-be-cached"
        client = Mock()
        client.base_url = "https://cm.harica.gr"
        client.list_certificates.return_value = [
            {
                "serial": "01",
                "status": "valid",
                "certificate": "PEM-ROOT",
                "nested": {"certificate": "PEM-NESTED", "keep": True},
            }
        ]
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.json"
            with (
                patch.dict(
                    "os.environ",
                    {
                        "HARICA_API_KEY": secret,
                        "HARICA_CLIENT_LANGUAGE": "it",
                    },
                    clear=True,
                ),
                patch("harica_client.cli._client_from_args", return_value=client),
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
            ):
                code = main(
                    ["cache", "refresh", "--cache-file", str(target)]
                )
            snapshot = read_cache(
                target,
                expected_environment="production",
            )

        self.assertEqual(code, 0)
        client.list_certificates.assert_called_once_with("all")
        self.assertEqual(snapshot.statuses, ("valid", "revoked", "expired"))
        self.assertNotIn("certificate", snapshot.certificates[0])
        self.assertNotIn("certificate", snapshot.certificates[0]["nested"])
        self.assertNotIn(secret, json.dumps(snapshot.certificates))
        self.assertIn("Cache aggiornata", output.getvalue())

    def test_cache_refresh_custom_url_requires_explicit_file(self) -> None:
        with (
            patch("harica_client.cli._client_from_args") as client_factory,
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            code = main(
                ["cache", "refresh", "--base-url", "https://cache.example.org"]
            )
        self.assertEqual(code, 2)
        client_factory.assert_not_called()

    def test_cache_status_and_delete_do_not_use_network(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.json"
            write_cache(
                target,
                environment="production",
                base_url="https://cm.harica.gr",
                certificates=[{"serial": "01", "status": "valid"}],
            )
            with (
                patch("harica_client.cli._client_from_args") as client_factory,
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
            ):
                status_code = main(
                    ["cache", "status", "--cache-file", str(target)]
                )
                delete_code = main(
                    ["cache", "delete", "--cache-file", str(target), "--yes"]
                )
                missing_status_code = main(
                    ["cache", "status", "--cache-file", str(target)]
                )

        self.assertEqual((status_code, delete_code, missing_status_code), (0, 0, 1))
        self.assertIn("Certificati: 1", output.getvalue())
        self.assertIn("Cache eliminata", output.getvalue())
        self.assertIn("Stato: non valida", output.getvalue())
        self.assertFalse(target.exists())
        client_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
