"""Guardian — runtime observation and self-healing for Python applications.

Public API
----------
.. autofunction:: guard
.. autofunction:: guardian_context
.. autofunction:: guardian_config

Pro features
~~~~~~~~~~~~
.. autoclass:: FailurePatternDetector
.. autoclass:: HealingAuditLog
"""

from devnog.guardian.config import GuardianConfig, guardian_config
from devnog.guardian.context import guardian_context
from devnog.guardian.middleware import guard

__all__ = [
    "guard",
    "guardian_context",
    "guardian_config",
    "GuardianConfig",
]
