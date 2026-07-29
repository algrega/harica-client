from __future__ import annotations

import io
import json
import unittest
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

from harica_client import (
    HaricaAuthError,
    HaricaClient,
    HaricaConfigurationError,
    HaricaHTTPError,
    HaricaRateLimitError,
    HaricaResponseError,
    RetryPolicy,
)
from harica_client.i18n import using_language


class _FakeResponse:
    def __init__(self, status: int, payload: bytes) -> None:
        self.status = status
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        pass


class _ScenarioTransport:
    def __init__(self, responses: list[tuple[int, dict[str, str], Any]]) -> None:
        self.responses = deque(responses)
        self.requests: list[dict[str, str]] = []
        self.url = "https://mock.harica.invalid"
        self._patcher = patch(
            "harica_client.client._open_without_redirects",
            side_effect=self._open,
        )

    def _open(self, request: Any, *, timeout: float) -> _FakeResponse:
        del timeout
        self.requests.append(
            {
                "path": urlsplit(request.full_url).path,
                "api_key": request.get_header("X-api-key", ""),
                "accept": request.get_header("Accept", ""),
                "user_agent": request.get_header("User-agent", ""),
            }
        )
        status, headers, body = self.responses.popleft()
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        if status >= 400:
            raise HTTPError(
                request.full_url,
                status,
                "simulated error",
                headers,
                io.BytesIO(payload),
            )
        return _FakeResponse(status, payload)

    def __enter__(self) -> "_ScenarioTransport":
        self._patcher.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._patcher.stop()


class HaricaClientTests(unittest.TestCase):
    def test_valid_list_and_headers(self) -> None:
        with _ScenarioTransport([(200, {}, [{"serialNumber": "01"}])]) as server:
            client = HaricaClient("secret", base_url=server.url)
            result = client.list_certificates("valid")

        self.assertEqual(result, [{"serialNumber": "01"}])
        self.assertEqual(
            server.requests[0]["path"],
            "/cm/v1/admin/certificates/list/valid",
        )
        self.assertEqual(server.requests[0]["api_key"], "secret")
        self.assertEqual(server.requests[0]["accept"], "application/json")
        self.assertEqual(server.requests[0]["user_agent"], "harica-client/0.18.0")

    def test_all_lists_and_combines_each_status(self) -> None:
        responses = [
            (200, {}, [{"serialNumber": "01"}]),
            (200, {}, {"data": [{"serialNumber": "02", "status": "Revoked"}]}),
            (200, {}, {"certificates": [{"serialNumber": "03"}]}),
        ]
        with _ScenarioTransport(responses) as server:
            client = HaricaClient("secret", base_url=server.url)
            result = client.list_certificates("all")

        self.assertEqual(
            [request["path"] for request in server.requests],
            [
                "/cm/v1/admin/certificates/list/valid",
                "/cm/v1/admin/certificates/list/revoked",
                "/cm/v1/admin/certificates/list/expired",
            ],
        )
        self.assertEqual(
            result,
            [
                {"serialNumber": "01", "status": "valid"},
                {"serialNumber": "02", "status": "Revoked"},
                {"serialNumber": "03", "status": "expired"},
            ],
        )

    def test_serial_is_url_encoded(self) -> None:
        with _ScenarioTransport([(200, {}, {"ok": True})]) as server:
            client = HaricaClient("secret", base_url=server.url)
            client.certificate_by_serial("AA/BB 01")

        self.assertEqual(
            server.requests[0]["path"],
            "/cm/v1/admin/certificates/serial/AA%2FBB%2001",
        )

    def test_429_uses_retry_after_then_succeeds(self) -> None:
        delays: list[float] = []
        responses = [
            (429, {"Retry-After": "2"}, {"message": "slow down"}),
            (200, {}, [{"serialNumber": "02"}]),
        ]
        with _ScenarioTransport(responses) as server:
            client = HaricaClient(
                "secret",
                base_url=server.url,
                retry_policy=RetryPolicy(max_attempts=2),
                sleep=delays.append,
            )
            result = client.list_certificates()

        self.assertEqual(result, [{"serialNumber": "02"}])
        self.assertEqual(delays, [2.0])
        self.assertEqual(len(server.requests), 2)

    def test_429_exhaustion_has_specific_error(self) -> None:
        responses = [
            (429, {"Retry-After": "0"}, {"message": "slow down"}),
            (429, {"Retry-After": "9"}, {"message": "still limited"}),
        ]
        with _ScenarioTransport(responses) as server:
            client = HaricaClient(
                "secret",
                base_url=server.url,
                retry_policy=RetryPolicy(max_attempts=2),
                sleep=lambda _delay: None,
            )
            with self.assertRaises(HaricaRateLimitError) as caught:
                client.list_certificates()

        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(caught.exception.retry_after, 9.0)
        self.assertIn("still limited", str(caught.exception))

    def test_auth_error_is_distinct(self) -> None:
        with _ScenarioTransport([(403, {}, {"message": "forbidden"})]) as server:
            client = HaricaClient("bad", base_url=server.url)
            with self.assertRaises(HaricaAuthError) as caught:
                client.list_certificates()

        self.assertEqual(caught.exception.status_code, 403)

    def test_non_json_response_is_distinct(self) -> None:
        with _ScenarioTransport([(200, {}, b"not-json")]) as server:
            client = HaricaClient("secret", base_url=server.url)
            with self.assertRaises(HaricaResponseError) as caught:
                client.list_certificates()

        self.assertEqual(caught.exception.body_preview, "not-json")

    def test_non_json_pem_response_has_no_preview(self) -> None:
        pem_bodies = (
            b"-----BEGIN CERTIFICATE-----\nSENSITIVE\n-----END CERTIFICATE-----",
            b"prefix\n-----BEGIN PRIVATE KEY-----\nSENSITIVE\n-----END PRIVATE KEY-----",
        )
        for body in pem_bodies:
            with self.subTest(body=body.splitlines()[0]):
                with _ScenarioTransport([(200, {}, body)]) as server:
                    client = HaricaClient("secret", base_url=server.url)
                    with self.assertRaises(HaricaResponseError) as caught:
                        client.list_certificates()

                self.assertEqual(caught.exception.body_preview, "")

    def test_remote_text_is_redacted_before_errors_are_exposed(self) -> None:
        secret = "FAKE-ASSESSMENT-KEY-DO-NOT-LOG"
        responses = [
            (403, {}, {"message": f"reflected {secret}"}),
            (200, {}, f"invalid response containing {secret}".encode()),
        ]
        with _ScenarioTransport(responses) as server:
            client = HaricaClient(secret, base_url=server.url)
            with self.assertRaises(HaricaAuthError) as auth_error:
                client.list_certificates()
            with self.assertRaises(HaricaResponseError) as response_error:
                client.list_certificates()

        self.assertNotIn(secret, str(auth_error.exception))
        self.assertNotIn(secret, auth_error.exception.body)
        self.assertIn("[REDACTED]", str(auth_error.exception))
        self.assertNotIn(secret, response_error.exception.body_preview)
        self.assertIn("[REDACTED]", response_error.exception.body_preview)

    def test_base_url_requires_https_except_for_loopback(self) -> None:
        with self.assertRaises(HaricaConfigurationError):
            HaricaClient("secret", base_url="http://example.org")

        self.assertEqual(
            HaricaClient("secret", base_url="http://127.0.0.1:8080/").base_url,
            "http://127.0.0.1:8080",
        )
        self.assertEqual(
            HaricaClient("secret", base_url="http://[::1]:8080/").base_url,
            "http://[::1]:8080",
        )

    def test_base_url_rejects_unsafe_or_ambiguous_components(self) -> None:
        invalid_urls = (
            "https:///missing-host",
            "https://user:password@example.org",
            "https://example.org?target=other",
            "https://example.org#fragment",
            "https://example.org:not-a-port",
        )
        for value in invalid_urls:
            with self.subTest(value=value), self.assertRaises(HaricaConfigurationError):
                HaricaClient("secret", base_url=value)

    def test_redirects_never_forward_the_api_key(self) -> None:
        secret = "FAKE-REDIRECT-ASSESSMENT-KEY"

        for status_code in (301, 302, 303, 307, 308):
            received: list[str | None] = []

            class TargetHandler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    received.append(self.headers.get("X-API-Key"))
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b"{}")

                def log_message(self, *_args: object) -> None:
                    pass

            class RedirectHandler(BaseHTTPRequestHandler):
                target_url = ""

                def do_GET(self) -> None:
                    self.send_response(status_code)
                    self.send_header("Location", self.target_url)
                    self.end_headers()

                def log_message(self, *_args: object) -> None:
                    pass

            target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
            source = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
            RedirectHandler.target_url = (
                f"http://127.0.0.1:{target.server_port}/capture"
            )
            threads = [
                Thread(target=server.serve_forever, daemon=True)
                for server in (target, source)
            ]
            for thread in threads:
                thread.start()
            try:
                client = HaricaClient(
                    secret,
                    base_url=f"http://127.0.0.1:{source.server_port}",
                    retry_policy=RetryPolicy(max_attempts=1),
                )
                with self.subTest(status_code=status_code), self.assertRaises(
                    HaricaHTTPError
                ) as caught:
                    client.list_certificates()
                self.assertEqual(caught.exception.status_code, status_code)
                self.assertEqual(received, [])
                self.assertNotIn(secret, str(caught.exception))
            finally:
                source.shutdown()
                target.shutdown()
                source.server_close()
                target.server_close()

    def test_api_key_is_required(self) -> None:
        with self.assertRaises(HaricaConfigurationError):
            HaricaClient("  ")

    def test_invalid_status_is_rejected_before_network(self) -> None:
        client = HaricaClient("secret")
        with self.assertRaises(HaricaConfigurationError):
            client.list_certificates("pending")

    def test_rate_limit_error_is_localized_and_keeps_api_detail(self) -> None:
        responses = [(429, {"Retry-After": "3"}, {"message": "server detail"})]
        with using_language("en"), _ScenarioTransport(responses) as server:
            client = HaricaClient(
                "secret",
                base_url=server.url,
                retry_policy=RetryPolicy(max_attempts=1),
            )
            with self.assertRaises(HaricaRateLimitError) as caught:
                client.list_certificates()

        message = str(caught.exception)
        self.assertIn("HARICA rate limit reached", message)
        self.assertIn("retry in about 3 seconds", message)
        self.assertIn("server detail", message)


if __name__ == "__main__":
    unittest.main()
