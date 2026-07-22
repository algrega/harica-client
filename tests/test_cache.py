from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from harica_client.cache import (
    CACHE_FILE_ENV,
    cache_age_hours,
    default_cache_path,
    delete_cache,
    read_cache,
    resolve_cache_path,
    write_cache,
)
from harica_client.errors import HaricaConfigurationError


class CacheTests(unittest.TestCase):
    NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)

    def _write_snapshot(
        self,
        target: Path,
        *,
        environment: str = "production",
        now: datetime | None = None,
    ) -> None:
        write_cache(
            target,
            environment=environment,
            base_url="https://cm.harica.gr",
            certificates=[{"serial": "01", "status": "valid"}],
            now=now or self.NOW,
        )

    def test_default_path_uses_xdg_and_environment(self) -> None:
        path = default_cache_path(
            "staging",
            environ={"XDG_CACHE_HOME": "/srv/harica-cache"},
        )
        self.assertEqual(
            path,
            Path("/srv/harica-cache/harica-client/certificates/staging.json"),
        )

    def test_default_path_falls_back_to_home(self) -> None:
        path = default_cache_path("production", environ={"HOME": "/home/harica"})
        self.assertEqual(
            path,
            Path("/home/harica/.cache/harica-client/certificates/production.json"),
        )

    def test_cache_path_precedence(self) -> None:
        explicit = resolve_cache_path(
            "production",
            explicit_path="/explicit/cache.json",
            environ={CACHE_FILE_ENV: "/environment/cache.json", "HOME": "/home/test"},
        )
        environment = resolve_cache_path(
            "production",
            environ={CACHE_FILE_ENV: "/environment/cache.json", "HOME": "/home/test"},
        )
        default = resolve_cache_path("production", environ={"HOME": "/home/test"})
        self.assertEqual(explicit, Path("/explicit/cache.json"))
        self.assertEqual(environment, Path("/environment/cache.json"))
        self.assertEqual(
            default,
            Path("/home/test/.cache/harica-client/certificates/production.json"),
        )

    def test_relative_xdg_and_empty_environment_file_are_rejected(self) -> None:
        with self.assertRaises(HaricaConfigurationError):
            default_cache_path(
                "production",
                environ={"XDG_CACHE_HOME": "relative"},
            )
        with self.assertRaises(HaricaConfigurationError):
            resolve_cache_path(
                "production",
                environ={CACHE_FILE_ENV: "", "HOME": "/home/test"},
            )

    def test_write_and_read_cache_with_secure_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.json"
            self._write_snapshot(target)
            snapshot = read_cache(
                target,
                expected_environment="production",
                now=self.NOW + timedelta(hours=2),
            )
            payload = json.loads(target.read_text(encoding="utf-8"))
            directory_mode = stat.S_IMODE(target.parent.stat().st_mode)
            file_mode = stat.S_IMODE(target.stat().st_mode)

        self.assertEqual(directory_mode, 0o700)
        self.assertEqual(file_mode, 0o600)
        self.assertEqual(snapshot.schema_version, 1)
        self.assertEqual(snapshot.statuses, ("valid", "revoked", "expired"))
        self.assertEqual(snapshot.certificates[0]["serial"], "01")
        self.assertEqual(cache_age_hours(snapshot, now=self.NOW + timedelta(hours=2)), 2)
        self.assertNotIn("apiKey", payload)
        self.assertNotIn("X-API-Key", payload)

    def test_missing_empty_invalid_json_and_schema_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.json"
            with self.assertRaises(HaricaConfigurationError):
                read_cache(missing, expected_environment="production", now=self.NOW)

            for name, content in (
                ("empty.json", ""),
                ("invalid.json", "{"),
                ("schema.json", '{"schemaVersion": 2}'),
            ):
                target = root / name
                target.write_text(content, encoding="utf-8")
                target.chmod(0o600)
                with self.assertRaises(HaricaConfigurationError):
                    read_cache(target, expected_environment="production", now=self.NOW)

    def test_environment_timestamp_statuses_and_max_age_are_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "cache.json"
            self._write_snapshot(target)

            with self.assertRaises(HaricaConfigurationError):
                read_cache(target, expected_environment="staging", now=self.NOW)
            with self.assertRaises(HaricaConfigurationError):
                read_cache(
                    target,
                    expected_environment="production",
                    max_age_hours=1,
                    now=self.NOW + timedelta(hours=2),
                )
            with self.assertRaises(HaricaConfigurationError):
                read_cache(
                    target,
                    expected_environment="production",
                    max_age_hours=0,
                    now=self.NOW,
                )
            for invalid_age in (float("nan"), float("inf")):
                with self.assertRaises(HaricaConfigurationError):
                    read_cache(
                        target,
                        expected_environment="production",
                        max_age_hours=invalid_age,
                        now=self.NOW,
                    )
            with self.assertRaises(HaricaConfigurationError):
                read_cache(
                    target,
                    expected_environment="production",
                    now=self.NOW - timedelta(seconds=1),
                )

            payload = json.loads(target.read_text(encoding="utf-8"))
            payload["statuses"] = ["valid"]
            target.write_text(json.dumps(payload), encoding="utf-8")
            target.chmod(0o600)
            with self.assertRaises(HaricaConfigurationError):
                read_cache(target, expected_environment="production", now=self.NOW)

    def test_symlink_open_permissions_wrong_owner_and_shared_directory_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe = root / "safe.json"
            self._write_snapshot(safe)

            link = root / "link.json"
            link.symlink_to(safe)
            with self.assertRaises(HaricaConfigurationError):
                read_cache(link, expected_environment="production", now=self.NOW)

            safe.chmod(0o640)
            with self.assertRaises(HaricaConfigurationError):
                read_cache(safe, expected_environment="production", now=self.NOW)
            safe.chmod(0o600)

            with patch("harica_client.cache.os.geteuid", return_value=os.geteuid() + 1):
                with self.assertRaises(HaricaConfigurationError):
                    read_cache(safe, expected_environment="production", now=self.NOW)

            root.chmod(0o750)
            with self.assertRaises(HaricaConfigurationError):
                read_cache(safe, expected_environment="production", now=self.NOW)

    def test_failed_atomic_replace_preserves_previous_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.json"
            self._write_snapshot(target)
            original = target.read_bytes()

            with patch("harica_client.cache.os.replace", side_effect=OSError("failure")):
                with self.assertRaises(HaricaConfigurationError):
                    write_cache(
                        target,
                        environment="production",
                        base_url="https://cm.harica.gr",
                        certificates=[{"serial": "02", "status": "valid"}],
                        now=self.NOW + timedelta(hours=1),
                    )

            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(list(target.parent.glob("*.tmp")), [])

    def test_delete_removes_only_cache_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.json"
            self._write_snapshot(target)
            parent = target.parent
            deleted = delete_cache(target)
            self.assertEqual(deleted, target)
            self.assertFalse(target.exists())
            self.assertTrue(parent.is_dir())


if __name__ == "__main__":
    unittest.main()
