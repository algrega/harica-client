from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harica_client.cli import (
    _client_from_args,
    _extract_rows,
    _filter_certificates,
    _print_table,
    _render_or_export,
    _without_certificate,
    _write_csv,
    build_parser,
    main,
)
from harica_client.errors import HaricaConfigurationError
from harica_client.credentials import (
    default_api_key_path,
    legacy_default_api_key_path,
    read_api_key_file,
    write_api_key_file,
)


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["version"])
        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue().strip(), "0.9.0")

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
                patch.dict("os.environ", {}, clear=True),
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
                patch.dict("os.environ", {}, clear=True),
                patch(
                    "harica_client.cli.getpass.getpass",
                    side_effect=["first-secret", "second-secret"],
                ),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                code = main(["auth", "set", "--api-key-file", str(target)])

        combined = output.getvalue() + errors.getvalue()
        self.assertEqual(code, 1)
        self.assertNotIn("first-secret", combined)
        self.assertNotIn("second-secret", combined)
        self.assertFalse(target.exists())

    def test_list_and_serial_load_key_file_with_clean_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "production.key"
            target.write_text("file-secret\n", encoding="utf-8")
            target.chmod(0o600)
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
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.dict(
                    "os.environ",
                    {"HARICA_API_KEY": secret, "HOME": directory},
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

    def test_auth_migrate_moves_legacy_key_without_printing_it(self) -> None:
        secret = "legacy-secret-not-for-output"
        output = io.StringIO()
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            environment = {"HOME": directory}
            legacy = legacy_default_api_key_path("production", environ=environment)
            destination = default_api_key_path("production", environ=environment)
            write_api_key_file(legacy, secret)
            with (
                patch.dict("os.environ", environment, clear=True),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                code = main(["auth", "migrate", "--environment", "production"])

            self.assertEqual(read_api_key_file(destination), secret)
            self.assertFalse(legacy.exists())

        combined = output.getvalue() + errors.getvalue()
        self.assertEqual(code, 0)
        self.assertNotIn(secret, combined)


if __name__ == "__main__":
    unittest.main()
