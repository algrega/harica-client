"""Client Python non ufficiale e in sola lettura per HARICA Certificate Manager."""

__version__ = "0.18.0"

from .client import Environment, HaricaClient, RetryPolicy
from .errors import (
    HaricaAuthError,
    HaricaConfigurationError,
    HaricaError,
    HaricaHTTPError,
    HaricaNetworkError,
    HaricaRateLimitError,
    HaricaResponseError,
)

__all__ = [
    "Environment",
    "HaricaAuthError",
    "HaricaClient",
    "HaricaConfigurationError",
    "HaricaError",
    "HaricaHTTPError",
    "HaricaNetworkError",
    "HaricaRateLimitError",
    "HaricaResponseError",
    "RetryPolicy",
]
