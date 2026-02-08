"""QA Gate checks — all built-in production-readiness checks."""

from devnog.qa.checks.base import QACheck
from devnog.qa.checks.error_handling import (
    QA001UnhandledEntryPointExceptions,
    QA002MissingRetryOnExternalCalls,
    QA003CatchAllWithoutReraise,
)
from devnog.qa.checks.timeouts import (
    QA004HTTPClientTimeout,
    QA005DatabaseOperationTimeout,
    QA006SocketConnectionTimeout,
)
from devnog.qa.checks.infrastructure import (
    QA007MissingHealthCheck,
    QA008NoGracefulShutdown,
    QA009MissingReadinessProbe,
    QA010HardcodedHostPort,
    QA011MissingSignalHandlers,
)
from devnog.qa.checks.data_safety import (
    QA012SQLWithoutParameterization,
    QA013MissingTransactionHandling,
)
from devnog.qa.checks.config import (
    QA014HardcodedSecrets,
    QA015DebugModeEnabled,
    QA016MissingEnvValidation,
)
from devnog.qa.checks.resilience import (
    QA017NoCircuitBreaker,
    QA018MissingBackoff,
    QA019UnboundedQueueGrowth,
)
from devnog.qa.checks.performance import (
    QA020NPlusOneQueryPattern,
    QA021SyncIOInAsyncContext,
)
from devnog.qa.checks.observability import (
    QA022MissingStructuredLogging,
    QA023NoRequestTracing,
    QA024MissingMetrics,
    QA025NoErrorReporting,
)

ALL_QA_CHECKS: list[type[QACheck]] = [
    # Error handling (QA-001 .. QA-003)
    QA001UnhandledEntryPointExceptions,
    QA002MissingRetryOnExternalCalls,
    QA003CatchAllWithoutReraise,
    # Timeouts (QA-004 .. QA-006)
    QA004HTTPClientTimeout,
    QA005DatabaseOperationTimeout,
    QA006SocketConnectionTimeout,
    # Infrastructure (QA-007 .. QA-011)
    QA007MissingHealthCheck,
    QA008NoGracefulShutdown,
    QA009MissingReadinessProbe,
    QA010HardcodedHostPort,
    QA011MissingSignalHandlers,
    # Data safety (QA-012 .. QA-013)
    QA012SQLWithoutParameterization,
    QA013MissingTransactionHandling,
    # Configuration (QA-014 .. QA-016)
    QA014HardcodedSecrets,
    QA015DebugModeEnabled,
    QA016MissingEnvValidation,
    # Resilience (QA-017 .. QA-019)
    QA017NoCircuitBreaker,
    QA018MissingBackoff,
    QA019UnboundedQueueGrowth,
    # Performance (QA-020 .. QA-021)
    QA020NPlusOneQueryPattern,
    QA021SyncIOInAsyncContext,
    # Observability (QA-022 .. QA-025)
    QA022MissingStructuredLogging,
    QA023NoRequestTracing,
    QA024MissingMetrics,
    QA025NoErrorReporting,
]

__all__ = ["QACheck", "ALL_QA_CHECKS"]
