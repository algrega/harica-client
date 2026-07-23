from __future__ import annotations

import base64
import io
import ssl
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from harica_client.certificate_download import (
    extract_certificate_pem,
    validate_download_destination,
    write_certificate_pem,
)
from harica_client.cli import main
from harica_client.errors import HaricaConfigurationError
from harica_client.i18n import using_language

CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUVLT5m4DSkG73Om1Dbm0E8u0xTXMwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwHhcNMjYwNzIzMDgyNjQwWhcNMjYw
NzI0MDgyNjQwWjAWMRQwEgYDVQQDDAtleGFtcGxlLm9yZzCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANZXElDZD5ICUh2rb+JTOj7WMJgHQ2T3mR/za9Z4
JA95C7NpaXhlKWOY3VO5oYHBYBCVqfs5WCHlA5NgWGIq3YT/EWXDcOvyNiB7jRpm
dwhvRCC2lrt3SJtKZPO492rBqj7Sia4A+SA3OG8YH18Z4yFikQo5iSDMxyZWiXyC
GUZzyetuQRkQMOa0f/Biw2h9bCjRdkMA7yStxU2tzwy2oyPomg8HgHIa0lAr9Vcn
giS9IAghaXUy7nh6pOrkSAgABRdROA61+bE03EEbL3zzeVGsQ+Eld8EMjqFWsTPB
xqMeUEu0S5f8tJwDnO0149NhcAQMpxw0QoBB2YLaUzya2ecCAwEAAaNTMFEwHQYD
VR0OBBYEFP/0noqpyCGSEG6Jr23hZ4p//RUcMB8GA1UdIwQYMBaAFP/0noqpyCGS
EG6Jr23hZ4p//RUcMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AD7XEDw+0DFYj7QqRsAjIPvlnPb3GYPQ1tI6RGVIp/67xyJP/ZmgRctXPT5pZWPt
SG141W19a+QuXnN2QtRAaJEGF9X3U1hIpDSTWWUM9tutVN+HW8K6PxtX5Tw02sBD
JiTGlSP0jF9OS/rH76ZswFasTEqHt7/EubelTOuNZAg3OIbQlcN7eoPSirJ9Dqlv
Ly1o9MSbR/4I5zcq4SWO/p2ERrib3c6vNxwq4ZTLKsqYhZBW8hu8tgmdfczkuNu9
141aiOkGSEeqSNY2XbZ62sb/etNO8m0xD0qpN1saN5foovM2kd/Wwv7i3cU5ZfP/
GiCvi59u7JjDeFD1Z0VBjEI=
-----END CERTIFICATE-----
"""


class CertificateExtractionTests(unittest.TestCase):
    def test_extracts_direct_nested_list_and_case_insensitive_fields(self) -> None:
        responses = (
            {"certificate": CERTIFICATE_PEM},
            {"data": {"Certificate": CERTIFICATE_PEM.replace("\n", "\r\n")}},
            [{"result": [{"CeRtIfIcAtE": CERTIFICATE_PEM}]}],
            {
                "certificate": CERTIFICATE_PEM,
                "nested": {"Certificate": CERTIFICATE_PEM},
            },
        )
        for response in responses:
            with self.subTest(response=response):
                self.assertEqual(extract_certificate_pem(response), CERTIFICATE_PEM)

    def test_converts_base64_der_to_pem(self) -> None:
        der = ssl.PEM_cert_to_DER_cert(CERTIFICATE_PEM)
        encoded = base64.b64encode(der).decode("ascii")

        self.assertEqual(
            extract_certificate_pem({"certificate": encoded}),
            CERTIFICATE_PEM,
        )

    def test_rejects_missing_empty_non_text_and_ambiguous_fields(self) -> None:
        different_der = bytearray(ssl.PEM_cert_to_DER_cert(CERTIFICATE_PEM))
        different_der[-1] ^= 1
        different_certificate = ssl.DER_cert_to_PEM_cert(bytes(different_der))
        invalid = (
            {},
            {"certificate": ""},
            {"certificate": None},
            {
                "certificate": CERTIFICATE_PEM,
                "wrapper": {"Certificate": different_certificate},
            },
        )
        for response in invalid:
            with self.subTest(response=response):
                with self.assertRaises(HaricaConfigurationError):
                    extract_certificate_pem(response)

    def test_rejects_chain_private_key_pkcs7_and_malformed_content(self) -> None:
        invalid = (
            CERTIFICATE_PEM + CERTIFICATE_PEM,
            "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----",
            "-----BEGIN PKCS7-----\nZmFrZQ==\n-----END PKCS7-----",
            "-----BEGIN PKCS12-----\nZmFrZQ==\n-----END PKCS12-----",
            "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----",
            base64.b64encode(b"not a certificate").decode("ascii"),
        )
        for certificate in invalid:
            with self.subTest(certificate=certificate[:40]):
                with self.assertRaises(HaricaConfigurationError):
                    extract_certificate_pem({"certificate": certificate})

    def test_errors_never_include_certificate_content(self) -> None:
        secret_fragment = "PRIVATE-TEST-CONTENT"
        with self.assertRaises(HaricaConfigurationError) as caught:
            extract_certificate_pem({"certificate": secret_fragment})
        self.assertNotIn(secret_fragment, str(caught.exception))


class CertificateDestinationTests(unittest.TestCase):
    def test_writes_atomically_creates_directories_and_sets_mode_0644(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "nested" / "certificate.pem"
            written = write_certificate_pem(target, CERTIFICATE_PEM)

            self.assertEqual(written, target)
            self.assertEqual(target.read_text(encoding="ascii"), CERTIFICATE_PEM)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
            self.assertEqual(list(target.parent.glob(f".{target.name}.*.tmp")), [])

    def test_existing_file_requires_force_and_force_replaces_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"
            target.write_text("old", encoding="ascii")

            with self.assertRaises(HaricaConfigurationError):
                validate_download_destination(target)
            write_certificate_pem(target, CERTIFICATE_PEM, force=True)
            self.assertEqual(target.read_text(encoding="ascii"), CERTIFICATE_PEM)

    def test_rejects_symlink_and_non_regular_destination_even_with_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular.pem"
            regular.write_text("old", encoding="ascii")
            symlink = root / "link.pem"
            symlink.symlink_to(regular)
            destination_directory = root / "directory.pem"
            destination_directory.mkdir()

            for target in (symlink, destination_directory):
                with self.subTest(target=target):
                    with self.assertRaises(HaricaConfigurationError):
                        validate_download_destination(target, force=True)

    def test_failed_replace_preserves_existing_file_and_removes_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"
            target.write_text("old", encoding="ascii")

            with (
                patch(
                    "harica_client.certificate_download.os.replace",
                    side_effect=OSError("simulated"),
                ),
                self.assertRaises(HaricaConfigurationError),
            ):
                write_certificate_pem(target, CERTIFICATE_PEM, force=True)

            self.assertEqual(target.read_text(encoding="ascii"), "old")
            self.assertEqual(list(target.parent.glob(f".{target.name}.*.tmp")), [])


class DownloadCliTests(unittest.TestCase):
    def test_download_saves_only_path_and_does_not_print_pem_or_api_key(self) -> None:
        api_key = "test-api-key-never-print"
        client = Mock()
        client.certificate_by_serial.return_value = {
            "data": {"Certificate": CERTIFICATE_PEM}
        }
        output = io.StringIO()
        errors = io.StringIO()

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"
            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                patch.dict("os.environ", {"HARICA_API_KEY": api_key}, clear=True),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                code = main(
                    [
                        "download",
                        "AA BB/01",
                        "--output",
                        str(target),
                    ]
                )

            self.assertEqual(target.read_text(encoding="ascii"), CERTIFICATE_PEM)

        rendered = output.getvalue() + errors.getvalue()
        self.assertEqual(code, 0)
        client.certificate_by_serial.assert_called_once_with("AA BB/01")
        self.assertEqual(rendered.strip(), str(target))
        self.assertNotIn("BEGIN CERTIFICATE", rendered)
        self.assertNotIn(api_key, rendered)

    def test_existing_destination_is_rejected_before_creating_client(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"
            target.write_text("old", encoding="ascii")
            errors = io.StringIO()

            with (
                patch("harica_client.cli._client_from_args") as client_factory,
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
            ):
                code = main(
                    ["download", "01", "--output", str(target)]
                )

            self.assertEqual(code, 1)
            client_factory.assert_not_called()
            self.assertEqual(target.read_text(encoding="ascii"), "old")

    def test_invalid_response_with_force_preserves_existing_file(self) -> None:
        client = Mock()
        client.certificate_by_serial.return_value = {"data": {"certificate": "bad"}}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"
            target.write_text("old", encoding="ascii")

            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                code = main(
                    [
                        "download",
                        "01",
                        "--output",
                        str(target),
                        "--force",
                    ]
                )

            self.assertEqual(code, 1)
            self.assertEqual(target.read_text(encoding="ascii"), "old")

    def test_request_error_does_not_create_destination(self) -> None:
        client = Mock()
        client.certificate_by_serial.side_effect = HaricaConfigurationError(
            "simulated request failure"
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"

            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                code = main(
                    ["download", "01", "--output", str(target)]
                )

            self.assertEqual(code, 1)
            self.assertFalse(target.exists())

    def test_validation_error_is_localized_in_english(self) -> None:
        client = Mock()
        client.certificate_by_serial.return_value = {"certificate": "bad"}
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"
            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
            ):
                code = main(
                    [
                        "download",
                        "01",
                        "--output",
                        str(target),
                        "--language",
                        "en",
                    ]
                )

        self.assertEqual(code, 1)
        self.assertIn("valid X.509 certificate", errors.getvalue())

    def test_output_is_required_and_help_is_bilingual(self) -> None:
        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit) as caught:
            main(["download", "01"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--output", errors.getvalue())

        output = io.StringIO()
        with (
            using_language("en"),
            redirect_stdout(output),
            self.assertRaises(SystemExit) as caught,
        ):
            main(["download", "--language", "en", "--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("Destination PEM file", output.getvalue())
