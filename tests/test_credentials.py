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
    read_api_key_file,
    resolve_api_key,
    write_api_key_file,
)
from harica_client.errors import HaricaConfigurationError


class CredentialTests(unittest.TestCase):
    def _platform_environment(self, directory: str) -> dict[str, str]:
        if os.name == "nt":
            return {"APPDATA": directory, "LOCALAPPDATA": directory}
        return {"HOME": directory}

    def _secret_file(self, directory: str, name: str, value: str) -> Path:
        path = Path(directory) / name
        if value:
            write_api_key_file(path, value)
        else:
            path.write_bytes(b"")
            if os.name != "nt":
                path.chmod(0o600)
        return path

    @unittest.skipIf(os.name == "nt", "test specifico per XDG/POSIX")
    def test_default_path_uses_xdg_and_environment(self) -> None:
        path = default_api_key_path(
            "staging",
            environ={"XDG_CONFIG_HOME": "/srv/harica-config"},
        )
        self.assertEqual(
            path,
            Path("/srv/harica-config/harica-client/credentials/staging.key"),
        )

    @unittest.skipIf(os.name == "nt", "test specifico per HOME/POSIX")
    def test_default_path_falls_back_to_home(self) -> None:
        path = default_api_key_path("production", environ={"HOME": "/home/harica"})
        self.assertEqual(
            path,
            Path("/home/harica/.config/harica-client/credentials/production.key"),
        )

    @unittest.skipIf(os.name == "nt", "test specifico per XDG/POSIX")
    def test_relative_xdg_path_is_rejected(self) -> None:
        with self.assertRaises(HaricaConfigurationError):
            default_api_key_path("production", environ={"XDG_CONFIG_HOME": "relative"})

    @unittest.skipUnless(os.name == "nt", "test specifico per Windows")
    def test_default_windows_path_uses_appdata_and_dpapi_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = default_api_key_path(
                "staging",
                environ={"APPDATA": directory},
            )
        self.assertEqual(
            path,
            Path(directory)
            / "harica-client"
            / "credentials"
            / "staging.key.dpapi",
        )

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
            platform_environment = self._platform_environment(directory)
            default_file = default_api_key_path(
                "production",
                environ=platform_environment,
            )
            write_api_key_file(default_file, "default-secret")
            credential = resolve_api_key(
                "production",
                environ={
                    **platform_environment,
                    "HARICA_API_KEY_FILE": str(environment_file),
                },
            )
        self.assertEqual(credential.api_key, "file-secret")
        self.assertEqual(credential.source, "HARICA_API_KEY_FILE")

    def test_clean_cron_environment_uses_default_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cron_environment = (
                {"APPDATA": directory, "PATH": os.environ.get("PATH", "")}
                if os.name == "nt"
                else {"HOME": directory, "PATH": "/usr/bin:/bin"}
            )
            default_file = default_api_key_path("development", environ=cron_environment)
            write_api_key_file(default_file, "cron-secret")
            credential = resolve_api_key("development", environ=cron_environment)
        self.assertEqual(credential.api_key, "cron-secret")
        self.assertEqual(credential.path, default_file)

    def test_set_creates_0700_directory_and_0600_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.key"
            write_api_key_file(target, "secret")
            if os.name != "nt":
                directory_mode = stat.S_IMODE(target.parent.stat().st_mode)
                file_mode = stat.S_IMODE(target.stat().st_mode)
            else:
                raw = target.read_bytes()
        if os.name != "nt":
            self.assertEqual(directory_mode, 0o700)
            self.assertEqual(file_mode, 0o600)
        else:
            self.assertNotIn(b"secret", raw)

    def test_rotation_replaces_value_and_preserves_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.key"
            write_api_key_file(target, "old-secret")
            write_api_key_file(target, "new-secret")
            value = read_api_key_file(target)
            mode = stat.S_IMODE(target.stat().st_mode) if os.name != "nt" else None
            temporary_files = list(target.parent.glob("*.tmp"))
        self.assertEqual(value, "new-secret")
        if os.name != "nt":
            self.assertEqual(mode, 0o600)
        self.assertEqual(temporary_files, [])

    def test_failed_rotation_preserves_previous_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private" / "production.key"
            write_api_key_file(target, "old-secret")
            original = target.read_bytes()

            with patch(
                "harica_client.platform_storage.os.replace",
                side_effect=OSError("failure"),
            ):
                with self.assertRaises(HaricaConfigurationError):
                    write_api_key_file(target, "new-secret")

            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(read_api_key_file(target), "old-secret")
            self.assertEqual(list(target.parent.glob("*.tmp")), [])

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

            if os.name != "nt":
                open_file = self._secret_file(directory, "open.key", "secret")
                open_file.chmod(0o640)
                with self.assertRaises(HaricaConfigurationError):
                    read_api_key_file(open_file)

                safe_file = self._secret_file(directory, "safe.key", "secret")
                symlink = Path(directory) / "link.key"
                symlink.symlink_to(safe_file)
                with self.assertRaises(HaricaConfigurationError):
                    read_api_key_file(symlink)

    @unittest.skipIf(os.name == "nt", "proprietario POSIX")
    def test_wrong_owner_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self._secret_file(directory, "secret.key", "secret")
            with patch(
                "harica_client.platform_storage.os.geteuid",
                return_value=os.geteuid() + 1,
            ):
                with self.assertRaises(HaricaConfigurationError):
                    read_api_key_file(target)

    @unittest.skipIf(os.name == "nt", "permessi directory POSIX")
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
        if os.name == "nt":
            with tempfile.TemporaryDirectory() as directory:
                destination = credential_destination(
                    "production",
                    environ={
                        "HARICA_API_KEY": "do-not-store",
                        "APPDATA": directory,
                    },
                )
            self.assertEqual(
                destination,
                Path(directory)
                / "harica-client"
                / "credentials"
                / "production.key.dpapi",
            )
            return
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
