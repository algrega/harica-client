from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harica_client.credentials import (
    credential_destination,
    default_api_key_path,
    delete_api_key_file,
    inspect_credential,
    legacy_default_api_key_path,
    migrate_legacy_api_key,
    read_api_key_file,
    resolve_api_key,
    write_api_key_file,
)
from harica_client.errors import HaricaConfigurationError


class CredentialTests(unittest.TestCase):
    def _secret_file(self, directory: str, name: str, value: str) -> Path:
        path = Path(directory) / name
        path.write_text(f"{value}\n", encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_default_path_uses_xdg_and_environment(self) -> None:
        path = default_api_key_path(
            "staging",
            environ={"XDG_CONFIG_HOME": "/srv/harica-config"},
        )
        self.assertEqual(
            path,
            Path("/srv/harica-config/harica-client/credentials/staging.key"),
        )

    def test_default_path_falls_back_to_home(self) -> None:
        path = default_api_key_path("production", environ={"HOME": "/home/harica"})
        self.assertEqual(
            path,
            Path("/home/harica/.config/harica-client/credentials/production.key"),
        )

    def test_relative_xdg_path_is_rejected(self) -> None:
        with self.assertRaises(HaricaConfigurationError):
            default_api_key_path("production", environ={"XDG_CONFIG_HOME": "relative"})

    def test_explicit_file_has_highest_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            explicit = self._secret_file(directory, "explicit.key", "explicit-secret")
            environment_file = self._secret_file(directory, "environment.key", "file-secret")
            credential = resolve_api_key(
                "production",
                explicit_path=explicit,
                environ={
                    "HARICA_API_KEY": "environment-secret",
                    "HARICA_API_KEY_FILE": str(environment_file),
                    "HOME": directory,
                },
            )
        self.assertEqual(credential.api_key, "explicit-secret")
        self.assertEqual(credential.source, "--api-key-file")

    def test_direct_environment_precedes_environment_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment_file = self._secret_file(directory, "environment.key", "file-secret")
            credential = resolve_api_key(
                "production",
                environ={
                    "HARICA_API_KEY": "environment-secret",
                    "HARICA_API_KEY_FILE": str(environment_file),
                    "HOME": directory,
                },
            )
        self.assertEqual(credential.api_key, "environment-secret")
        self.assertEqual(credential.source, "HARICA_API_KEY")
        self.assertNotIn("environment-secret", repr(credential))

    def test_environment_file_precedes_default_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment_file = self._secret_file(directory, "environment.key", "file-secret")
            default_file = default_api_key_path("production", environ={"HOME": directory})
            write_api_key_file(default_file, "default-secret")
            credential = resolve_api_key(
                "production",
                environ={
                    "HARICA_API_KEY_FILE": str(environment_file),
                    "HOME": directory,
                },
            )
        self.assertEqual(credential.api_key, "file-secret")
        self.assertEqual(credential.source, "HARICA_API_KEY_FILE")

    def test_clean_cron_environment_uses_default_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cron_environment = {"HOME": directory, "PATH": "/usr/bin:/bin"}
            default_file = default_api_key_path("development", environ=cron_environment)
            write_api_key_file(default_file, "cron-secret")
            credential = resolve_api_key("development", environ=cron_environment)
        self.assertEqual(credential.api_key, "cron-secret")
        self.assertEqual(credential.path, default_file)

    def test_legacy_default_is_read_when_new_path_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {"HOME": directory}
            legacy = legacy_default_api_key_path("production", environ=environment)
            write_api_key_file(legacy, "legacy-secret")
            credential = resolve_api_key("production", environ=environment)

        self.assertEqual(credential.api_key, "legacy-secret")
        self.assertEqual(credential.source, "file legacy harica-safe")
        self.assertEqual(credential.path, legacy)

    def test_migration_moves_legacy_key_without_changing_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {"HOME": directory}
            legacy = legacy_default_api_key_path("production", environ=environment)
            destination = default_api_key_path("production", environ=environment)
            write_api_key_file(legacy, "legacy-secret")

            source, migrated = migrate_legacy_api_key(
                "production",
                environ=environment,
            )

            self.assertEqual(source, legacy)
            self.assertEqual(migrated, destination)
            self.assertFalse(legacy.exists())
            self.assertEqual(read_api_key_file(destination), "legacy-secret")
            self.assertFalse(legacy.parent.parent.exists())

    def test_set_creates_0700_directory_and_0600_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.key"
            write_api_key_file(target, "secret")
            directory_mode = stat.S_IMODE(target.parent.stat().st_mode)
            file_mode = stat.S_IMODE(target.stat().st_mode)
        self.assertEqual(directory_mode, 0o700)
        self.assertEqual(file_mode, 0o600)

    def test_rotation_replaces_value_and_preserves_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.key"
            write_api_key_file(target, "old-secret")
            write_api_key_file(target, "new-secret")
            value = read_api_key_file(target)
            mode = stat.S_IMODE(target.stat().st_mode)
            temporary_files = list(target.parent.glob("*.tmp"))
        self.assertEqual(value, "new-secret")
        self.assertEqual(mode, 0o600)
        self.assertEqual(temporary_files, [])

    def test_delete_removes_only_secret_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.key"
            write_api_key_file(target, "secret")
            parent = target.parent
            delete_api_key_file(target)
            self.assertFalse(target.exists())
            self.assertTrue(parent.is_dir())

    def test_missing_empty_symlink_and_open_permissions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.key"
            with self.assertRaises(HaricaConfigurationError):
                read_api_key_file(missing)

            empty = self._secret_file(directory, "empty.key", "")
            with self.assertRaises(HaricaConfigurationError):
                read_api_key_file(empty)

            open_file = self._secret_file(directory, "open.key", "secret")
            open_file.chmod(0o640)
            with self.assertRaises(HaricaConfigurationError):
                read_api_key_file(open_file)

            safe_file = self._secret_file(directory, "safe.key", "secret")
            symlink = Path(directory) / "link.key"
            symlink.symlink_to(safe_file)
            with self.assertRaises(HaricaConfigurationError):
                read_api_key_file(symlink)

    def test_wrong_owner_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self._secret_file(directory, "secret.key", "secret")
            with patch("harica_client.credentials.os.geteuid", return_value=os.geteuid() + 1):
                with self.assertRaises(HaricaConfigurationError):
                    read_api_key_file(target)

    def test_file_in_shared_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            shared = Path(directory) / "shared"
            shared.mkdir(mode=0o700)
            target = self._secret_file(str(shared), "secret.key", "secret")
            shared.chmod(0o750)
            with self.assertRaises(HaricaConfigurationError):
                read_api_key_file(target)

    def test_status_never_contains_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self._secret_file(directory, "secret.key", "do-not-display")
            status = inspect_credential(
                "production",
                explicit_path=target,
                environ={"HOME": directory},
            )
        self.assertTrue(status.valid)
        self.assertNotIn("do-not-display", status.detail)
        self.assertNotIn("do-not-display", repr(status))

    def test_destination_ignores_direct_environment_secret(self) -> None:
        destination = credential_destination(
            "production",
            environ={"HARICA_API_KEY": "do-not-store", "HOME": "/home/harica"},
        )
        self.assertEqual(
            destination,
            Path("/home/harica/.config/harica-client/credentials/production.key"),
        )


if __name__ == "__main__":
    unittest.main()
