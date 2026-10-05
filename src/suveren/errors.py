"""Exception hierarchy used across Suveren."""


class SuverenError(Exception):
    """Base class for all expected Suveren errors."""


class InvalidTargetError(SuverenError, ValueError):
    """The user supplied something that is not a valid domain."""


class TargetNotFoundError(SuverenError):
    """The domain does not exist in DNS (NXDOMAIN)."""


class ModuleError(SuverenError):
    """A data source could not be queried; the message is shown to the user as-is."""
