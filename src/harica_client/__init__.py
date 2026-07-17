"""Client Python per le API Certificate Manager di HARICA."""

__version__ = "0.12.0"

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
