from __future__ import annotations

import io
import json
import unittest
from collections import deque
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

from harica_client import (
    HaricaAuthError,
    HaricaClient,
    HaricaConfigurationError,
    HaricaRateLimitError,
    HaricaResponseError,
    RetryPolicy,
)


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
        self._patcher = patch("harica_client.client.urlopen", side_effect=self._open)

    def _open(self, request: Any, *, timeout: float) -> _FakeResponse:
        del timeout
        self.requests.append(
            {
                "path": urlsplit(request.full_url).path,
                "api_key": request.get_header("X-api-key", ""),
                "accept": request.get_header("Accept", ""),
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

    def test_api_key_is_required(self) -> None:
        with self.assertRaises(HaricaConfigurationError):
            HaricaClient("  ")

    def test_invalid_status_is_rejected_before_network(self) -> None:
        client = HaricaClient("secret")
        with self.assertRaises(HaricaConfigurationError):
            client.list_certificates("pending")


if __name__ == "__main__":
    unittest.main()
