from __future__ import annotations

import base64
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from harica_client.cache import read_cache, resolve_cache_path, write_cache
from harica_client.credentials import (
    read_api_key_file,
    select_credential_location,
    write_api_key_file,
)
from harica_client.errors import HaricaConfigurationError
from harica_client.platform_storage import is_reparse_point
from harica_client.windows_dpapi import (
    DpapiError,
    _decode_envelope,
    _encode_envelope,
    protect,
    unprotect,
)


class DpapiEnvelopeTests(unittest.TestCase):
    def test_envelope_rejects_plaintext_truncation_and_wrong_type(self) -> None:
        invalid = (
            b"plaintext-api-key",
            b"HARICA-CLIENT-DPAPI/1 api-key\n",
            b"HARICA-CLIENT-DPAPI/1 api-key\n%%%\n",
            _encode_envelope(b"ciphertext", purpose="cache"),
        )
        for envelope in invalid:
            with self.subTest(envelope=envelope):
                with self.assertRaises(DpapiError):
                    _decode_envelope(envelope, purpose="api-key")

    def test_envelope_is_versioned_and_round_trips_ciphertext(self) -> None:
        ciphertext = b"\x00\x01opaque\xff"
        envelope = _encode_envelope(ciphertext, purpose="cache")

        self.assertTrue(envelope.startswith(b"HARICA-CLIENT-DPAPI/1 cache\n"))
        self.assertEqual(_decode_envelope(envelope, purpose="cache"), ciphertext)

    def test_reparse_attribute_is_recognized_without_creating_a_junction(self) -> None:
        flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        metadata = SimpleNamespace(
            st_mode=stat.S_IFDIR,
            st_file_attributes=flag,
        )
        self.assertTrue(is_reparse_point(metadata))


@unittest.skipUnless(os.name == "nt", "DPAPI è disponibile soltanto su Windows")
class NativeWindowsStorageTests(unittest.TestCase):
    NOW = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)

    def test_dpapi_round_trip_and_purpose_separation(self) -> None:
        secret = b"native-windows-secret"
        envelope = protect(secret, purpose="api-key")

        self.assertEqual(unprotect(envelope, purpose="api-key"), secret)
        self.assertNotIn(secret, envelope)
        with self.assertRaises(DpapiError):
            unprotect(envelope, purpose="cache")

    def test_tampered_dpapi_payload_is_rejected(self) -> None:
        envelope = protect(b"secret", purpose="api-key")
        ciphertext = bytearray(_decode_envelope(envelope, purpose="api-key"))
        ciphertext[len(ciphertext) // 2] ^= 1
        tampered = _encode_envelope(bytes(ciphertext), purpose="api-key")

        with self.assertRaises(DpapiError):
            unprotect(tampered, purpose="api-key")

    def test_key_and_cache_files_never_contain_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "credentials" / "production.key.dpapi"
            cache = root / "cache" / "production.json.dpapi"

            write_api_key_file(key, "api-key-plaintext-marker")
            write_cache(
                cache,
                environment="production",
                base_url="https://cm.harica.gr",
                certificates=[{"serial": "plaintext-cache-marker"}],
                now=self.NOW,
            )

            self.assertEqual(read_api_key_file(key), "api-key-plaintext-marker")
            self.assertNotIn(b"api-key-plaintext-marker", key.read_bytes())
            self.assertNotIn(b"plaintext-cache-marker", cache.read_bytes())
            self.assertEqual(
                read_cache(
                    cache,
                    expected_environment="production",
                    now=self.NOW,
                ).certificates[0]["serial"],
                "plaintext-cache-marker",
            )

    def test_plaintext_key_and_wrong_cache_envelope_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "plain.key"
            key.write_text("manual-plaintext-key", encoding="utf-8")
            cache = root / "wrong.json.dpapi"
            cache.write_bytes(protect(b"{}", purpose="api-key"))

            with self.assertRaisesRegex(
                HaricaConfigurationError,
                "auth set|auth set",
            ):
                read_api_key_file(key)
            with self.assertRaises(HaricaConfigurationError):
                read_cache(
                    cache,
                    expected_environment="production",
                    now=self.NOW,
                )

    def test_relative_unc_device_and_alternate_stream_paths_are_rejected(self) -> None:
        invalid = (
            "relative.key",
            r"\\server\share\production.key.dpapi",
            r"\\?\C:\secrets\production.key.dpapi",
            r"C:\secrets\production.key.dpapi:stream",
        )
        for path in invalid:
            with self.subTest(path=path):
                with self.assertRaises(HaricaConfigurationError):
                    select_credential_location("production", explicit_path=path)
                with self.assertRaises(HaricaConfigurationError):
                    resolve_cache_path("production", explicit_path=path)

    def test_truncated_or_tampered_files_do_not_expose_their_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "production.key.dpapi"
            write_api_key_file(key, "never-show-this-value")
            encoded = key.read_bytes().splitlines()[1]
            ciphertext = bytearray(base64.b64decode(encoded))
            ciphertext[-1] ^= 1
            key.write_bytes(_encode_envelope(bytes(ciphertext), purpose="api-key"))

            with self.assertRaises(HaricaConfigurationError) as caught:
                read_api_key_file(key)
            rendered = str(caught.exception)
            self.assertNotIn("never-show-this-value", rendered)
            self.assertNotIn(base64.b64encode(bytes(ciphertext)).decode(), rendered)


if __name__ == "__main__":
    unittest.main()
