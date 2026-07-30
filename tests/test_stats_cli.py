from __future__ import annotations

import csv
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from harica_client.cache import default_cache_path, write_cache
from harica_client.cli import main


class StatsCliTests(unittest.TestCase):
    def _records(self) -> list[dict[str, object]]:
        now = datetime.now(UTC)
        return [
            {
                "serial": "01",
                "status": "valid",
                "validFrom": (now - timedelta(days=10)).isoformat(),
                "validTo": (now + timedelta(days=5)).isoformat(),
                "isRevoked": False,
                "revokedAt": None,
                "dN": "C=IT,CN=portal.example.org",
                "friendlyName": "=Portal",
                "user": "=Mario",
                "userEmail": "pki@example.org",
            },
            {
                "serial": "02",
                "status": "revoked",
                "validFrom": (now - timedelta(days=100)).isoformat(),
                "validTo": (now + timedelta(days=50)).isoformat(),
                "isRevoked": True,
                "revokedAt": (now - timedelta(days=2)).isoformat(),
                "dN": "C=IT,CN=old.example.org",
                "friendlyName": "Old",
                "user": "",
                "userEmail": "",
            },
        ]

    def _write_cache(
        self,
        root: Path,
        *,
        age_hours: float = 0,
        records: list[dict[str, object]] | None = None,
    ) -> Path:
        target = root / "private" / "production.json"
        write_cache(
            target,
            environment="production",
            base_url="https://cm.harica.gr",
            certificates=self._records() if records is None else records,
            now=datetime.now(UTC) - timedelta(hours=age_hours),
        )
        return target

    def test_all_stats_commands_use_cache_without_credentials_or_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self._write_cache(Path(directory))
            for command in ("summary", "expirations", "owners", "quality"):
                with self.subTest(command=command):
                    output = io.StringIO()
                    errors = io.StringIO()
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
                                "stats",
                                command,
                                "--cache-file",
                                str(target),
                                "--json",
                            ]
                        )
                    self.assertEqual(code, 0)
                    json.loads(output.getvalue())
                    client_factory.assert_not_called()

    def test_summary_json_data_is_language_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self._write_cache(Path(directory))
            outputs: list[dict[str, object]] = []
            for language in ("it", "en"):
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    code = main(
                        [
                            "stats",
                            "summary",
                            "--language",
                            language,
                            "--cache-file",
                            str(target),
                            "--json",
                        ]
                    )
                self.assertEqual(code, 0)
                outputs.append(json.loads(output.getvalue()))

        self.assertEqual(outputs[0]["total"], outputs[1]["total"])
        self.assertEqual(outputs[0]["statusCounts"], outputs[1]["statusCounts"])
        self.assertEqual(outputs[0]["expiryBuckets"], outputs[1]["expiryBuckets"])

    def test_language_flag_works_at_every_stats_level_and_last_value_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "missing.json")
            commands = (
                ["--language", "en", "stats", "summary", "--cache-file", missing],
                ["stats", "--language", "en", "summary", "--cache-file", missing],
                ["stats", "summary", "--language", "en", "--cache-file", missing],
                [
                    "stats",
                    "--language",
                    "it",
                    "summary",
                    "--language",
                    "en",
                    "--cache-file",
                    missing,
                ],
            )
            for arguments in commands:
                with self.subTest(arguments=arguments):
                    errors = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                        code = main(arguments)
                    self.assertEqual(code, 2)
                    self.assertIn("Cache file not found", errors.getvalue())

    def test_csv_exports_stable_headers_and_protects_formulas(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self._write_cache(root)
            owners_csv = root / "owners.csv"
            quality_csv = root / "quality.csv"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                owners_code = main(
                    [
                        "stats",
                        "owners",
                        "--cache-file",
                        str(target),
                        "--csv",
                        str(owners_csv),
                    ]
                )
                quality_code = main(
                    [
                        "stats",
                        "quality",
                        "--cache-file",
                        str(target),
                        "--csv",
                        str(quality_csv),
                    ]
                )
            with owners_csv.open(encoding="utf-8-sig", newline="") as stream:
                owner_rows = list(csv.DictReader(stream))
            with quality_csv.open(encoding="utf-8-sig", newline="") as stream:
                quality_reader = csv.DictReader(stream)
                quality_rows = list(quality_reader)
                quality_headers = quality_reader.fieldnames

        self.assertEqual((owners_code, quality_code), (0, 0))
        self.assertEqual(
            list(owner_rows[0]),
            [
                "userEmail",
                "user",
                "total",
                "valid",
                "revoked",
                "expired",
                "unknown",
                "expiringWithin30Days",
            ],
        )
        populated_owner = next(row for row in owner_rows if row["userEmail"])
        self.assertEqual(populated_owner["user"], "'=Mario")
        self.assertEqual(quality_headers, ["serial", "CN", "friendlyName", "issue"])
        self.assertTrue(quality_rows)

    def test_empty_quality_csv_keeps_stable_headers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "private" / "production.json"
            write_cache(
                target,
                environment="production",
                base_url="https://cm.harica.gr",
                certificates=[],
            )
            export = root / "quality.csv"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "stats",
                        "quality",
                        "--cache-file",
                        str(target),
                        "--csv",
                        str(export),
                    ]
                )
            with export.open(encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                rows = list(reader)

        self.assertEqual(code, 0)
        self.assertEqual(reader.fieldnames, ["serial", "CN", "friendlyName", "issue"])
        self.assertEqual(rows, [])

    def test_expirations_table_is_localized_and_sanitized(self) -> None:
        malicious = "portal.example.org\x1b[2J\u202e"
        with tempfile.TemporaryDirectory() as directory:
            records = self._records()
            records[0]["dN"] = f"C=IT,CN={malicious}"
            target = self._write_cache(Path(directory), records=records)
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "--language",
                        "en",
                        "stats",
                        "expirations",
                        "--cache-file",
                        str(target),
                    ]
                )

        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("Days remaining", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn(r"\x1b[2J\u202e", rendered)

    def test_expirations_warns_about_invalid_dates_and_rejects_invalid_within(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = self._records()
            records[0]["validTo"] = "invalid"
            target = self._write_cache(Path(directory), records=records)
            errors = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                code = main(
                    [
                        "stats",
                        "expirations",
                        "--cache-file",
                        str(target),
                    ]
                )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                invalid_code = main(
                    [
                        "stats",
                        "expirations",
                        "--cache-file",
                        str(target),
                        "--within",
                        "0",
                    ]
                )

        self.assertEqual(code, 0)
        self.assertEqual(invalid_code, 2)
        self.assertIn("Avviso", errors.getvalue())

    def test_max_cache_age_and_missing_cache_never_fall_back_to_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = self._write_cache(root, age_hours=3)
            missing = root / "missing.json"
            with (
                patch("harica_client.cli._client_from_args") as client_factory,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                old_code = main(
                    [
                        "stats",
                        "summary",
                        "--cache-file",
                        str(old),
                        "--max-cache-age",
                        "1",
                    ]
                )
                missing_code = main(
                    [
                        "stats",
                        "summary",
                        "--cache-file",
                        str(missing),
                    ]
                )

        self.assertEqual((old_code, missing_code), (2, 2))
        client_factory.assert_not_called()

    def test_minimal_cron_environment_uses_default_cache(self) -> None:
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
            target = default_cache_path("production", environ=environment)
            write_cache(
                target,
                environment="production",
                base_url="https://cm.harica.gr",
                certificates=self._records(),
            )
            output = io.StringIO()
            with (
                patch.dict("os.environ", environment, clear=True),
                patch("harica_client.cli._client_from_args") as client_factory,
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
            ):
                code = main(["stats", "summary", "--json"])

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["total"], 2)
        client_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
