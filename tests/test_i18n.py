from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harica_client import HaricaClient
from harica_client.cache import write_cache
from harica_client.cli import _render_or_export, main
from harica_client.credentials import (
    default_api_key_path,
    read_api_key_file,
    write_api_key_file,
)
from harica_client.errors import HaricaConfigurationError
from harica_client.i18n import (
    LanguageSelectionError,
    default_language_path,
    resolve_language,
    resolve_language_preference,
    using_language,
    write_saved_language,
)


class InternationalizationTests(unittest.TestCase):
    def _platform_environment(self, directory: str) -> dict[str, str]:
        if os.name == "nt":
            return {"APPDATA": directory, "LOCALAPPDATA": directory}
        return {"HOME": directory}

    def _help(self, arguments: list[str], environment: dict[str, str] | None = None) -> str:
        output = io.StringIO()
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            selected_environment = self._platform_environment(directory)
            selected_environment.update(environment or {})
            with (
                patch.dict("os.environ", selected_environment, clear=True),
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

    def test_stats_json_help_describes_reports_without_certificate_wording(self) -> None:
        cases = (
            ("it", "Stampa il report in formato JSON"),
            ("en", "Print the report as JSON"),
        )
        for language, expected in cases:
            with self.subTest(language=language):
                stats_help = self._help(
                    ["--language", language, "stats", "summary", "--help"]
                )
                list_help = self._help(["--language", language, "list", "--help"])

                self.assertIn(expected, stats_help)
                self.assertNotIn("certificate", stats_help)
                self.assertIn("certificate", list_help)

    def test_persistent_language_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self._platform_environment(directory)
            output = io.StringIO()
            with (
                patch.dict("os.environ", environment, clear=True),
                redirect_stdout(output),
            ):
                set_code = main(["language", "set", "en"])
                status_code = main(["language", "status"])

            path = default_language_path(environ=environment)
            self.assertEqual((set_code, status_code), (0, 0))
            self.assertEqual(path.read_text(encoding="utf-8"), "en\n")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertIn("Default language saved", output.getvalue())
            self.assertIn("Language: en", output.getvalue())
            self.assertIn("Source: saved preference", output.getvalue())

            rendered = self._help(["--help"], environment)
            self.assertIn("Show the version", rendered)

            reset_output = io.StringIO()
            with (
                patch.dict("os.environ", environment, clear=True),
                redirect_stdout(reset_output),
            ):
                reset_code = main(["language", "reset"])
            self.assertEqual(reset_code, 0)
            self.assertFalse(path.exists())
            self.assertIn("Language preference removed", reset_output.getvalue())

    def test_language_precedence_includes_saved_preference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self._platform_environment(directory)
            write_saved_language("en", environ=environment)

            saved = resolve_language_preference(["version"], environ=environment)
            from_environment = resolve_language_preference(
                ["version"],
                environ={**environment, "HARICA_CLIENT_LANGUAGE": "it"},
            )
            from_flag = resolve_language_preference(
                ["--language", "en", "version"],
                environ={**environment, "HARICA_CLIENT_LANGUAGE": "it"},
            )

        self.assertEqual((saved.language, saved.source), ("en", "saved"))
        self.assertEqual(
            (from_environment.language, from_environment.source),
            ("it", "environment"),
        )
        self.assertEqual((from_flag.language, from_flag.source), ("en", "flag"))

    @unittest.skipIf(os.name == "nt", "test specifico per XDG/POSIX")
    def test_saved_language_uses_xdg_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {"XDG_CONFIG_HOME": directory}
            path = write_saved_language("en", environ=environment)
            preference = resolve_language_preference([], environ=environment)

        self.assertEqual(path, Path(directory) / "harica-client/language")
        self.assertEqual(preference.language, "en")

    @unittest.skipUnless(os.name == "nt", "test specifico per Windows")
    def test_saved_language_uses_appdata_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {"APPDATA": directory}
            path = write_saved_language("en", environ=environment)
            preference = resolve_language_preference([], environ=environment)

        self.assertEqual(path, Path(directory) / "harica-client/language")
        self.assertEqual(preference.language, "en")

    @unittest.skipIf(os.name == "nt", "permessi POSIX")
    def test_unsafe_saved_language_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self._platform_environment(directory)
            path = default_language_path(environ=environment)
            path.parent.mkdir(mode=0o700, parents=True)
            path.write_text("en\n", encoding="utf-8")
            path.chmod(0o666)

            with self.assertRaisesRegex(LanguageSelectionError, "scrivibile"):
                resolve_language_preference([], environ=environment)

    def test_explicit_override_can_repair_invalid_saved_language(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self._platform_environment(directory)
            path = default_language_path(environ=environment)
            path.parent.mkdir(mode=0o700, parents=True)
            path.write_text("invalid\n", encoding="utf-8")
            path.chmod(0o600)

            with (
                patch.dict("os.environ", environment, clear=True),
                redirect_stdout(io.StringIO()),
            ):
                code = main(["--language", "it", "language", "set", "en"])

            preference = resolve_language_preference([], environ=environment)

        self.assertEqual(code, 0)
        self.assertEqual(preference.language, "en")

    def test_flag_works_before_and_after_commands(self) -> None:
        cases = (
            ["--language", "en", "list", "--help"],
            ["list", "--language", "en", "--help"],
            ["auth", "--language", "en", "status", "--help"],
            ["auth", "status", "--language", "en", "--help"],
            ["cache", "--language", "en", "status", "--help"],
            ["cache", "status", "--language", "en", "--help"],
            ["--language", "en", "download", "--help"],
            ["download", "--language", "en", "--help"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                self.assertIn("Show this help message", self._help(list(arguments)))

    def test_cache_status_and_confirmation_are_localized_in_english(self) -> None:
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
                patch.dict("os.environ", {"HOME": directory}, clear=True),
                patch("builtins.input", return_value="yes") as input_mock,
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
            ):
                status_code = main(
                    [
                        "cache",
                        "status",
                        "--language",
                        "en",
                        "--cache-file",
                        str(target),
                    ]
                )
                delete_code = main(
                    [
                        "cache",
                        "delete",
                        "--language",
                        "en",
                        "--cache-file",
                        str(target),
                    ]
                )

        self.assertEqual((status_code, delete_code), (0, 0))
        self.assertIn("Cache environment: production", output.getvalue())
        self.assertIn("Cache deleted", output.getvalue())
        self.assertIn("Delete the cache", input_mock.call_args.args[0])
        self.assertIn("[y/N]", input_mock.call_args.args[0])

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
            cron_environment = {
                **self._platform_environment(directory),
                "PATH": os.environ.get("PATH", ""),
                "HARICA_CLIENT_LANGUAGE": "en",
            }
            key = default_api_key_path("production", environ=cron_environment)
            write_api_key_file(key, "cron-secret")
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
