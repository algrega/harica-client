"""Eccezioni pubbliche di harica-client."""

from __future__ import annotations

from typing import Any


class HaricaError(Exception):
    """Errore base del client HARICA."""


class HaricaConfigurationError(HaricaError):
    """Configurazione locale assente o non valida."""


class HaricaNetworkError(HaricaError):
    """Errore di rete dopo l'esaurimento dei tentativi."""


class HaricaHTTPError(HaricaError):
    """Risposta HTTP non riuscita."""

    def __init__(
        self,
        status_code: int,
        message: str,
        *,
        body: str = "",
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.request_id = request_id


class HaricaAuthError(HaricaHTTPError):
    """API key mancante, non valida o priva dei permessi richiesti."""


class HaricaRateLimitError(HaricaHTTPError):
    """Rate limit ancora attivo dopo l'esaurimento dei tentativi."""

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None,
        body: str = "",
        request_id: str | None = None,
    ) -> None:
        super().__init__(429, message, body=body, request_id=request_id)
        self.retry_after = retry_after


class HaricaResponseError(HaricaError):
    """La risposta ricevuta non rispetta il formato JSON atteso."""

    def __init__(self, message: str, *, body_preview: str = "") -> None:
        super().__init__(message)
        self.body_preview = body_preview


def error_message_from_json(value: Any) -> str | None:
    """Estrae un messaggio utile da strutture d'errore JSON comuni."""
    if not isinstance(value, dict):
        return None
    for key in ("message", "Message", "error", "Error", "detail", "title"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None
