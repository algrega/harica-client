"""Client HTTP sincrono per le API Certificate Manager di HARICA."""

from __future__ import annotations

import json
import random
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from . import __version__
from .errors import (
    HaricaAuthError,
    HaricaConfigurationError,
    HaricaHTTPError,
    HaricaNetworkError,
    HaricaRateLimitError,
    HaricaResponseError,
    error_message_from_json,
)
from .i18n import tr


class Environment(str, Enum):
    """Ambienti Certificate Manager documentati da HARICA."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"


BASE_URLS: dict[Environment, str] = {
    Environment.PRODUCTION: "https://cm.harica.gr",
    Environment.STAGING: "https://cm-stg.harica.gr",
    Environment.DEVELOPMENT: "https://cm-dev.harica.gr",
}


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Politica di retry per rate limit ed errori temporanei."""

    max_attempts: int = 4
    base_delay: float = 1.0
    max_delay: float = 60.0
    jitter: float = 0.25

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError(tr("retry_attempts_min"))
        if self.base_delay < 0 or self.max_delay < 0 or self.jitter < 0:
            raise ValueError(tr("retry_values_non_negative"))


class HaricaClient:
    """Client minimale con API key, retry controllato e risposte JSON."""

    RETRYABLE_STATUS_CODES = frozenset({429, 502, 503, 504})

    def __init__(
        self,
        api_key: str,
        *,
        environment: Environment | str = Environment.PRODUCTION,
        base_url: str | None = None,
        timeout: float = 30.0,
        retry_policy: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        random_source: Callable[[], float] = random.random,
    ) -> None:
        if not api_key or not api_key.strip():
            raise HaricaConfigurationError(tr("api_key_missing"))
        if timeout <= 0:
            raise HaricaConfigurationError(tr("timeout_positive"))

        try:
            selected_environment = Environment(environment)
        except ValueError as exc:
            allowed = ", ".join(item.value for item in Environment)
            raise HaricaConfigurationError(
                tr("environment_invalid", environment=environment, allowed=allowed)
            ) from exc

        resolved_url = base_url or BASE_URLS[selected_environment]
        if not resolved_url.startswith(("https://", "http://")):
            raise HaricaConfigurationError(tr("base_url_scheme"))

        self._api_key = api_key.strip()
        self.environment = selected_environment
        self.base_url = resolved_url.rstrip("/")
        self.timeout = timeout
        self.retry_policy = retry_policy or RetryPolicy()
        self._sleep = sleep
        self._random = random_source

    def list_certificates(
        self,
        status: str = "valid",
        *,
        query: Mapping[str, str | int | float | bool | None] | None = None,
    ) -> Any:
        """Elenca i certificati enterprise admin per stato."""
        normalized = status.lower()
        if normalized == "all":
            return self._list_all_certificates(query=query)
        if normalized not in {"valid", "revoked", "expired"}:
            raise HaricaConfigurationError(tr("status_invalid"))
        return self._get_json(f"/cm/v1/admin/certificates/list/{normalized}", query=query)

    def _list_all_certificates(
        self,
        *,
        query: Mapping[str, str | int | float | bool | None] | None = None,
    ) -> list[Any]:
        """Unisce le risposte degli endpoint valid, revoked ed expired."""
        certificates: list[Any] = []
        for status in ("valid", "revoked", "expired"):
            response = self.list_certificates(status, query=query)
            for row in self._certificate_rows(response):
                if isinstance(row, Mapping):
                    certificate = dict(row)
                    certificate.setdefault("status", status)
                    certificates.append(certificate)
                else:
                    certificates.append(row)
        return certificates

    @staticmethod
    def _certificate_rows(response: Any) -> list[Any]:
        if isinstance(response, list):
            return response
        if isinstance(response, Mapping):
            for key in ("certificates", "items", "results", "data"):
                candidate = response.get(key)
                if isinstance(candidate, list):
                    return candidate
            return [response]
        raise HaricaResponseError(tr("list_format_unexpected"))

    def certificate_by_serial(self, serial_number: str) -> Any:
        """Cerca un certificato enterprise admin per numero seriale."""
        serial = serial_number.strip()
        if not serial:
            raise HaricaConfigurationError(tr("serial_empty"))
        encoded = quote(serial, safe="")
        return self._get_json(f"/cm/v1/admin/certificates/serial/{encoded}")

    def _get_json(
        self,
        path: str,
        *,
        query: Mapping[str, str | int | float | bool | None] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        if query:
            clean_query = {key: value for key, value in query.items() if value is not None}
            if clean_query:
                url = f"{url}?{urlencode(clean_query)}"

        last_network_error: BaseException | None = None
        for attempt in range(1, self.retry_policy.max_attempts + 1):
            request = Request(
                url,
                method="GET",
                headers={
                    "Accept": "application/json",
                    "X-API-Key": self._api_key,
                    "User-Agent": f"harica-client/{__version__}",
                },
            )
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    return self._decode_json(body, status_code=response.status)
            except HTTPError as exc:
                try:
                    body = exc.read().decode("utf-8", errors="replace")
                    headers = exc.headers
                    request_id = headers.get("X-Request-ID") or headers.get("Request-ID")
                    retry_after = self._parse_retry_after(headers.get("Retry-After"))
                finally:
                    exc.close()

                should_retry = (
                    exc.code in self.RETRYABLE_STATUS_CODES
                    and attempt < self.retry_policy.max_attempts
                )
                if should_retry:
                    self._sleep(self._delay(attempt, retry_after=retry_after))
                    continue
                self._raise_http_error(
                    exc.code,
                    body,
                    retry_after=retry_after,
                    request_id=request_id,
                )
            except (URLError, TimeoutError, socket.timeout) as exc:
                last_network_error = exc
                if attempt < self.retry_policy.max_attempts:
                    self._sleep(self._delay(attempt, retry_after=None))
                    continue
                reason = getattr(exc, "reason", exc)
                raise HaricaNetworkError(
                    tr("network_failed_attempts", attempts=attempt, reason=reason)
                ) from exc

        raise HaricaNetworkError(tr("network_failed", reason=last_network_error))

    def _delay(self, attempt: int, *, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(max(0.0, retry_after), self.retry_policy.max_delay)
        exponential = self.retry_policy.base_delay * (2 ** (attempt - 1))
        jitter = self.retry_policy.jitter * self._random()
        return min(exponential + jitter, self.retry_policy.max_delay)

    @staticmethod
    def _parse_retry_after(value: str | None) -> float | None:
        if not value:
            return None
        try:
            return max(0.0, float(value.strip()))
        except ValueError:
            try:
                target = parsedate_to_datetime(value)
                if target.tzinfo is None:
                    target = target.replace(tzinfo=timezone.utc)
                return max(0.0, (target - datetime.now(timezone.utc)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                return None

    @staticmethod
    def _decode_json(body: str, *, status_code: int) -> Any:
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            content = body[:300]
            raise HaricaResponseError(
                tr("non_json_response", status_code=status_code),
                body_preview=content,
            ) from exc

    @classmethod
    def _raise_http_error(
        cls,
        status_code: int,
        body: str,
        *,
        retry_after: float | None,
        request_id: str | None,
    ) -> None:
        parsed: Any = None
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            pass
        detail = error_message_from_json(parsed)
        suffix = f": {detail}" if detail else ""

        if status_code in {401, 403}:
            raise HaricaAuthError(
                status_code,
                tr("auth_rejected", status_code=status_code, suffix=suffix),
                body=body[:1000],
                request_id=request_id,
            )
        if status_code == 429:
            wait_hint = (
                tr("retry_hint", seconds=retry_after) if retry_after is not None else ""
            )
            raise HaricaRateLimitError(
                tr("rate_limit", wait_hint=wait_hint, suffix=suffix),
                retry_after=retry_after,
                body=body[:1000],
                request_id=request_id,
            )
        raise HaricaHTTPError(
            status_code,
            tr("request_rejected", status_code=status_code, suffix=suffix),
            body=body[:1000],
            request_id=request_id,
        )
