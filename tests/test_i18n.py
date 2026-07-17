from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harica_client import HaricaClient
from harica_client.cli import _render_or_export, main
from harica_client.credentials import read_api_key_file, write_api_key_file
from harica_client.errors import HaricaConfigurationError
from harica_client.i18n import resolve_language, using_language


class InternationalizationTests(unittest.TestCase):
    def _help(self, arguments: list[str], environment: dict[str, str] | None = None) -> str:
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch.dict("os.environ", environment or {}, clear=True),
            redirect_stdout(output),
            redirect_stderr(errors),
            self.assertRaises(SystemExit) as caught,
        ):
            main(arguments)
        self.assertEqual(caught.exception.code, 0)
        return output.getvalue() + errors.getvalue()

    def test_default_language_is_italian(self) -> None:
        rendered = self._help(["--help"])
        self.assertIn("Mostra la versione", rendered)
        self.assertIn("opzioni:", rendered)

    def test_environment_selects_english(self) -> None:
        rendered = self._help(["--help"], {"HARICA_CLIENT_LANGUAGE": "en"})
        self.assertIn("Show the version", rendered)
        self.assertIn("options:", rendered)

    def test_flag_works_before_and_after_commands(self) -> None:
        cases = (
            ["--language", "en", "list", "--help"],
            ["list", "--language", "en", "--help"],
            ["auth", "--language", "en", "status", "--help"],
            ["auth", "status", "--language", "en", "--help"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                self.assertIn("Show this help message", self._help(list(arguments)))

    def test_last_flag_wins_and_flag_precedes_environment(self) -> None:
        rendered = self._help(
            ["--language", "it", "list", "--language", "en", "--help"],
            {"HARICA_CLIENT_LANGUAGE": "it"},
        )
        self.assertIn("Certificate status", rendered)
        self.assertEqual(
            resolve_language(
                ["--language", "en", "version"],
                environ={"HARICA_CLIENT_LANGUAGE": "it"},
            ),
            "en",
        )

    def test_invalid_or_missing_language_exits_two_without_traceback(self) -> None:
        for arguments, environment in (
            (["--language", "fr", "version"], {}),
            (["version", "--language"], {}),
            (["version"], {"HARICA_CLIENT_LANGUAGE": "fr"}),
        ):
            output = io.StringIO()
            errors = io.StringIO()
            with (
                patch.dict("os.environ", environment, clear=True),
                redirect_stdout(output),
                redirect_stderr(errors),
                self.assertRaises(SystemExit) as caught,
            ):
                main(arguments)
            combined = output.getvalue() + errors.getvalue()
            self.assertEqual(caught.exception.code, 2)
            self.assertNotIn("Traceback", combined)
            self.assertIn("errore:", combined)

    def test_argparse_errors_are_localized(self) -> None:
        errors = io.StringIO()
        with (
            patch.dict("os.environ", {}, clear=True),
            redirect_stderr(errors),
            self.assertRaises(SystemExit) as caught,
        ):
            main(["list", "--status", "pending"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("scelta non valida", errors.getvalue())

    def test_english_auth_lifecycle_does_not_expose_secret(self) -> None:
        secret = "english-secret-not-for-output"
        output = io.StringIO()
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "credentials" / "production.key"
            with (
                patch.dict("os.environ", {}, clear=True),
                patch("harica_client.cli.getpass.getpass", side_effect=[secret, secret]),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                set_code = main(
                    ["auth", "set", "--language", "en", "--api-key-file", str(target)]
                )
                status_code = main(
                    ["auth", "status", "--language", "en", "--api-key-file", str(target)]
                )
                delete_code = main(
                    [
                        "auth",
                        "delete",
                        "--language",
                        "en",
                        "--api-key-file",
                        str(target),
                        "--yes",
                    ]
                )

        combined = output.getvalue() + errors.getvalue()
        self.assertEqual((set_code, status_code, delete_code), (0, 0, 0))
        self.assertIn("API key saved", combined)
        self.assertIn("Source:", combined)
        self.assertIn("API key deleted", combined)
        self.assertNotIn(secret, combined)

    def test_confirmation_accepts_both_languages(self) -> None:
        for language, answer in (("it", "yes"), ("en", "sì")):
            with self.subTest(language=language, answer=answer):
                with tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "credentials" / "production.key"
                    write_api_key_file(target, "secret")
                    with (
                        patch.dict("os.environ", {}, clear=True),
                        patch("builtins.input", return_value=answer),
                        redirect_stdout(io.StringIO()),
                    ):
                        code = main(
                            [
                                "auth",
                                "delete",
                                "--language",
                                language,
                                "--api-key-file",
                                str(target),
                            ]
                        )
                    self.assertEqual(code, 0)
                    self.assertFalse(target.exists())

    def test_json_and_csv_data_are_language_independent(self) -> None:
        data = [{"serialNumber": "01", "dN": "C=IT,CN=portal.example.org"}]
        json_outputs: list[object] = []
        csv_outputs: list[bytes] = []
        for language in ("it", "en"):
            output = io.StringIO()
            with using_language(language), redirect_stdout(output):
                _render_or_export(data, SimpleNamespace(csv=None, json=True, force=False))
            json_outputs.append(json.loads(output.getvalue()))

            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "certificates.csv"
                with using_language(language), redirect_stdout(io.StringIO()):
                    _render_or_export(
                        data,
                        SimpleNamespace(csv=target, json=False, force=False),
                    )
                csv_outputs.append(target.read_bytes())

        self.assertEqual(json_outputs[0], json_outputs[1])
        self.assertEqual(csv_outputs[0], csv_outputs[1])

    def test_clean_cron_environment_uses_english(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / ".config/harica-client/credentials/production.key"
            write_api_key_file(key, "cron-secret")
            cron_environment = {
                "HOME": directory,
                "PATH": "/usr/bin:/bin",
                "HARICA_CLIENT_LANGUAGE": "en",
            }
            with (
                patch.dict("os.environ", cron_environment, clear=True),
                redirect_stdout(output),
            ):
                code = main(["auth", "status", "--environment", "production"])

        self.assertEqual(code, 0)
        self.assertIn("Status: valid", output.getvalue())
        self.assertIn("Source: default file", output.getvalue())
        self.assertNotIn("cron-secret", output.getvalue())

    def test_client_and_credential_errors_follow_active_language(self) -> None:
        with using_language("en"):
            with self.assertRaisesRegex(HaricaConfigurationError, "API key is missing"):
                HaricaClient("  ")
            with tempfile.TemporaryDirectory() as directory:
                missing = Path(directory) / "missing.key"
                with self.assertRaisesRegex(HaricaConfigurationError, "not found"):
                    read_api_key_file(missing)


if __name__ == "__main__":
    unittest.main()
