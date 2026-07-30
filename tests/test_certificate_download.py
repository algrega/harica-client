from __future__ import annotations

import base64
import io
import os
import ssl
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from harica_client.certificate_download import (
    CertificateSummary,
    _parse_asn1_time,
    _parse_name,
    _parse_name_details,
    automatic_download_filename,
    certificate_summary_from_pem,
    extract_certificate_pem,
    validate_download_destination,
    write_certificate_pem,
)
from harica_client.cli import build_parser, main
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


def _tlv(tag: int, value: bytes) -> bytes:
    if len(value) < 128:
        length = bytes((len(value),))
    else:
        encoded_length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
        length = bytes((0x80 | len(encoded_length),)) + encoded_length
    return bytes((tag,)) + length + value


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

    def test_extracts_stable_summary_from_certificate(self) -> None:
        summary = certificate_summary_from_pem(CERTIFICATE_PEM)

        self.assertEqual(
            summary,
            CertificateSummary(
                serial_number="54B4F99B80D2906EF73A6D436E6D04F2ED314D73",
                subject="CN=example.org",
                issuer="CN=example.org",
                not_before="2026-07-23T08:26:40Z",
                not_after="2026-07-24T08:26:40Z",
                common_names=("example.org",),
            ),
        )

    def test_expired_certificate_is_parsed_without_date_rejection(self) -> None:
        der = ssl.PEM_cert_to_DER_cert(CERTIFICATE_PEM)
        der = der.replace(b"260723082640Z", b"200723082640Z")
        der = der.replace(b"260724082640Z", b"200724082640Z")
        expired_pem = ssl.DER_cert_to_PEM_cert(der)

        summary = certificate_summary_from_pem(expired_pem)

        self.assertEqual(summary.not_before, "2020-07-23T08:26:40Z")
        self.assertEqual(summary.not_after, "2020-07-24T08:26:40Z")

    def test_name_supports_utf8_unknown_oid_multivalue_and_escaping(self) -> None:
        common_name = _tlv(0x06, b"\x55\x04\x03") + _tlv(
            0x0C,
            " Portale, città ".encode(),
        )
        unknown = _tlv(0x06, b"\x2A\x03\x04") + _tlv(
            0x0C,
            b"custom+value",
        )
        name = _tlv(0x31, _tlv(0x30, common_name) + _tlv(0x30, unknown))

        self.assertEqual(
            _parse_name(name, 0, len(name)),
            r"CN=\ Portale\, città\ +1.2.3.4=custom\+value",
        )

    def test_unknown_directory_string_is_rendered_as_hex(self) -> None:
        attribute = _tlv(0x06, b"\x55\x04\x03") + _tlv(0x04, b"\x00\xFF")
        name = _tlv(0x31, _tlv(0x30, attribute))

        self.assertEqual(_parse_name(name, 0, len(name)), r"CN=\#00FF")

    def test_utc_and_generalized_times_are_normalized_to_utc(self) -> None:
        self.assertEqual(
            _parse_asn1_time(0x17, b"500101000000Z"),
            "1950-01-01T00:00:00Z",
        )
        self.assertEqual(
            _parse_asn1_time(0x18, b"20510102030405+0100"),
            "2051-01-02T02:04:05Z",
        )


class AutomaticFilenameTests(unittest.TestCase):
    def _summary(
        self,
        *common_names: str,
        serial_number: str = "AABB01",
    ) -> CertificateSummary:
        return CertificateSummary(
            serial_number=serial_number,
            subject="",
            issuer="",
            not_before="2020-01-01T00:00:00Z",
            not_after="2030-01-01T00:00:00Z",
            common_names=common_names,
        )

    def test_uses_normal_common_name_and_preserves_case(self) -> None:
        self.assertEqual(
            automatic_download_filename(self._summary("Portal.Example.org")),
            "Portal.Example.org.pem",
        )

    def test_converts_wildcard_and_sanitizes_unsafe_characters(self) -> None:
        cases = (
            ("*.example.org", "wildcard.example.org.pem"),
            ("Ｐortal.example.org", "Portal.example.org.pem"),
            ("Portale città", "Portale_citt_.pem"),
            ("../../etc/passwd", "_.._etc_passwd.pem"),
            ("name/with\\controls\x00\x1b", "name_with_controls_.pem"),
        )
        for common_name, expected in cases:
            with self.subTest(common_name=common_name):
                self.assertEqual(
                    automatic_download_filename(self._summary(common_name)),
                    expected,
                )

    def test_falls_back_to_serial_for_missing_or_unusable_common_name(self) -> None:
        for common_names in ((), ("",), ("***",), ("é",)):
            with self.subTest(common_names=common_names):
                self.assertEqual(
                    automatic_download_filename(self._summary(*common_names)),
                    "AABB01.pem",
                )

    def test_accepts_identical_common_names_and_rejects_different_values(self) -> None:
        self.assertEqual(
            automatic_download_filename(
                self._summary(" example.org ", "example.org")
            ),
            "example.org.pem",
        )
        with self.assertRaises(HaricaConfigurationError):
            automatic_download_filename(
                self._summary("one.example.org", "two.example.org")
            )

    def test_long_name_is_truncated_with_deterministic_hash(self) -> None:
        common_name = f"{'a' * 220}.example.org"
        first = automatic_download_filename(self._summary(common_name))
        second = automatic_download_filename(self._summary(common_name))

        self.assertEqual(first, second)
        self.assertEqual(len(first.removesuffix(".pem")), 200)
        self.assertRegex(first, r"-[0-9a-f]{12}\.pem$")

    def test_windows_reserved_names_are_prefixed(self) -> None:
        cases = ("CON", "con.txt", "PRN", "AUX", "NUL", "COM1", "com9.log", "LPT1")
        for common_name in cases:
            with self.subTest(common_name=common_name):
                filename = automatic_download_filename(self._summary(common_name))
                self.assertTrue(filename.startswith("_"))
                self.assertTrue(filename.endswith(".pem"))

    def test_name_parser_collects_common_names_structurally(self) -> None:
        first = _tlv(0x06, b"\x55\x04\x03") + _tlv(0x0C, b"one.example.org")
        second = _tlv(0x06, b"\x55\x04\x03") + _tlv(0x0C, b"two.example.org")
        name = (
            _tlv(0x31, _tlv(0x30, first))
            + _tlv(0x31, _tlv(0x30, second))
        )

        rendered, common_names = _parse_name_details(name, 0, len(name))

        self.assertEqual(rendered, "CN=one.example.org, CN=two.example.org")
        self.assertEqual(common_names, ("one.example.org", "two.example.org"))


class CertificateDestinationTests(unittest.TestCase):
    def test_writes_atomically_creates_directories_and_sets_mode_0644(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "nested" / "certificate.pem"
            written = write_certificate_pem(target, CERTIFICATE_PEM)

            self.assertEqual(written, target)
            self.assertEqual(target.read_text(encoding="ascii"), CERTIFICATE_PEM)
            if os.name != "nt":
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

    @unittest.skipIf(os.name == "nt", "creazione symlink non sempre autorizzata")
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
    def test_download_saves_file_and_prints_italian_summary_without_secrets(self) -> None:
        api_key = "test-api-key-never-print"
        client = Mock()
        client.certificate_by_serial.return_value = {
            "data": {"Certificate": CERTIFICATE_PEM, "status": "revoked"}
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
                        "--language",
                        "it",
                    ]
                )

            self.assertEqual(target.read_text(encoding="ascii"), CERTIFICATE_PEM)

        rendered = output.getvalue() + errors.getvalue()
        self.assertEqual(code, 0)
        client.certificate_by_serial.assert_called_once_with("AA BB/01")
        self.assertEqual(
            rendered.strip().splitlines(),
            [
                f"Percorso: {target}",
                "Seriale: 54B4F99B80D2906EF73A6D436E6D04F2ED314D73",
                "Soggetto: CN=example.org",
                "Emittente: CN=example.org",
                "Valido dal: 2026-07-23T08:26:40Z",
                "Valido fino al: 2026-07-24T08:26:40Z",
            ],
        )
        self.assertNotIn("BEGIN CERTIFICATE", rendered)
        self.assertNotIn(api_key, rendered)

    def test_download_without_output_uses_cn_in_current_directory(self) -> None:
        client = Mock()
        client.certificate_by_serial.return_value = {"certificate": CERTIFICATE_PEM}
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "example.org.pem"
            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                patch(
                    "harica_client.certificate_download.Path.cwd",
                    return_value=Path(directory),
                ),
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
            ):
                code = main(["download", "01", "--language", "it"])

            self.assertEqual(target.read_text(encoding="ascii"), CERTIFICATE_PEM)

        self.assertEqual(code, 0)
        client.certificate_by_serial.assert_called_once_with("01")
        self.assertIn(f"Percorso: {target}", output.getvalue())

    def test_automatic_destination_collision_requires_force(self) -> None:
        client = Mock()
        client.certificate_by_serial.return_value = {"certificate": CERTIFICATE_PEM}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "example.org.pem"
            target.write_text("old", encoding="ascii")
            current_directory = patch(
                "harica_client.certificate_download.Path.cwd",
                return_value=Path(directory),
            )
            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                current_directory,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                rejected = main(["download", "01"])

            self.assertEqual(rejected, 2)
            self.assertEqual(target.read_text(encoding="ascii"), "old")

            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                patch(
                    "harica_client.certificate_download.Path.cwd",
                    return_value=Path(directory),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                replaced = main(["download", "01", "--force"])

            self.assertEqual(replaced, 0)
            self.assertEqual(target.read_text(encoding="ascii"), CERTIFICATE_PEM)

    @unittest.skipIf(os.name == "nt", "creazione symlink non sempre autorizzata")
    def test_automatic_destination_rejects_symlink_even_with_force(self) -> None:
        client = Mock()
        client.certificate_by_serial.return_value = {"certificate": CERTIFICATE_PEM}
        with tempfile.TemporaryDirectory() as directory:
            victim = Path(directory) / "victim.pem"
            victim.write_text("old", encoding="ascii")
            target = Path(directory) / "example.org.pem"
            target.symlink_to(victim)

            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                patch(
                    "harica_client.certificate_download.Path.cwd",
                    return_value=Path(directory),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                code = main(["download", "01", "--force"])

            self.assertEqual(code, 2)
            self.assertTrue(target.is_symlink())
            self.assertEqual(victim.read_text(encoding="ascii"), "old")

    def test_explicit_output_does_not_require_unambiguous_common_name(self) -> None:
        client = Mock()
        client.certificate_by_serial.return_value = {"certificate": CERTIFICATE_PEM}
        summary = CertificateSummary(
            serial_number="01",
            subject="CN=one.example.org, CN=two.example.org",
            issuer="CN=issuer",
            not_before="2020-01-01T00:00:00Z",
            not_after="2030-01-01T00:00:00Z",
            common_names=("one.example.org", "two.example.org"),
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "chosen.pem"
            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                patch(
                    "harica_client.cli.certificate_summary_from_pem",
                    return_value=summary,
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                code = main(
                    ["download", "01", "--output", str(target)]
                )

            self.assertEqual(code, 0)
            self.assertEqual(target.read_text(encoding="ascii"), CERTIFICATE_PEM)

    def test_download_summary_is_localized_in_english(self) -> None:
        client = Mock()
        client.certificate_by_serial.return_value = {"certificate": CERTIFICATE_PEM}
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"
            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
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

        self.assertEqual(code, 0)
        self.assertIn(f"Path: {target}", output.getvalue())
        self.assertIn("Serial: 54B4F99B80D2906EF73A6D436E6D04F2ED314D73", output.getvalue())
        self.assertIn("Subject: CN=example.org", output.getvalue())
        self.assertIn("Issuer: CN=example.org", output.getvalue())
        self.assertIn("Valid from: 2026-07-23T08:26:40Z", output.getvalue())
        self.assertIn("Valid until: 2026-07-24T08:26:40Z", output.getvalue())

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

            self.assertEqual(code, 2)
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

            self.assertEqual(code, 2)
            self.assertEqual(target.read_text(encoding="ascii"), "old")

    def test_summary_error_with_force_preserves_existing_file(self) -> None:
        client = Mock()
        client.certificate_by_serial.return_value = {"certificate": CERTIFICATE_PEM}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"
            target.write_text("old", encoding="ascii")

            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                patch(
                    "harica_client.cli.certificate_summary_from_pem",
                    side_effect=HaricaConfigurationError("simulated summary failure"),
                ),
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

            self.assertEqual(code, 2)
            self.assertEqual(target.read_text(encoding="ascii"), "old")

    def test_summary_neutralizes_terminal_controls(self) -> None:
        client = Mock()
        client.certificate_by_serial.return_value = {"certificate": CERTIFICATE_PEM}
        malicious = "CN=example.org\x1b[2J\x07\u202e"
        summary = CertificateSummary(
            serial_number="01",
            subject=malicious,
            issuer="CN=issuer",
            not_before="2020-01-01T00:00:00Z",
            not_after="2030-01-01T00:00:00Z",
        )
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "certificate.pem"
            with (
                patch("harica_client.cli._client_from_args", return_value=client),
                patch(
                    "harica_client.cli.certificate_summary_from_pem",
                    return_value=summary,
                ),
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
            ):
                code = main(
                    ["download", "01", "--output", str(target)]
                )

        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn(r"\x1b[2J\x07\u202e", rendered)

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

            self.assertEqual(code, 2)
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

        self.assertEqual(code, 2)
        self.assertIn("valid X.509 certificate", errors.getvalue())

    def test_output_is_optional_and_help_is_bilingual(self) -> None:
        arguments = build_parser().parse_args(["download", "01"])
        self.assertIsNone(arguments.output)

        output = io.StringIO()
        with (
            using_language("en"),
            redirect_stdout(output),
            self.assertRaises(SystemExit) as caught,
        ):
            main(["download", "--language", "en", "--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("Destination PEM file", output.getvalue())
        self.assertIn("if omitted", output.getvalue())
