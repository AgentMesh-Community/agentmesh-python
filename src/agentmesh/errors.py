"""Error codes and the one exception type the SDK raises (SPEC.md 12)."""

from __future__ import annotations

from enum import Enum
from typing import Any

__all__ = ["ErrorCode", "MeshError", "RejectedError", "RETRYABLE_CODES"]


class ErrorCode(str, Enum):
    """The protocol's error codes. Same strings as the TypeScript SDK."""

    TRANSPORT_TIMEOUT = "TRANSPORT_TIMEOUT"
    TRANSPORT_NO_RESPONDERS = "TRANSPORT_NO_RESPONDERS"
    TRANSPORT_PERMISSION_DENIED = "TRANSPORT_PERMISSION_DENIED"
    INVALID_ENVELOPE = "INVALID_ENVELOPE"
    INVALID_VERSION = "INVALID_VERSION"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    INVALID_MANIFEST = "INVALID_MANIFEST"
    INVALID_QUERY = "INVALID_QUERY"
    TASK_NOT_FOUND = "TASK_NOT_FOUND"
    TASK_INVALID_TRANSITION = "TASK_INVALID_TRANSITION"
    TASK_NOT_CANCELABLE = "TASK_NOT_CANCELABLE"
    TASK_EXPIRED = "TASK_EXPIRED"
    AGENT_UNAVAILABLE = "AGENT_UNAVAILABLE"
    REQUEST_QUEUED = "REQUEST_QUEUED"
    AGENT_OVERLOADED = "AGENT_OVERLOADED"
    OFFERING_NOT_FOUND = "OFFERING_NOT_FOUND"
    INPUT_INVALID = "INPUT_INVALID"
    CONTENT_TYPE_NOT_SUPPORTED = "CONTENT_TYPE_NOT_SUPPORTED"
    UNAUTHORIZED = "UNAUTHORIZED"
    SEALING_REQUIRED = "SEALING_REQUIRED"
    COST_LIMIT_EXCEEDED = "COST_LIMIT_EXCEEDED"
    BUDGET_INSUFFICIENT = "BUDGET_INSUFFICIENT"
    DEADLINE_UNMEETABLE = "DEADLINE_UNMEETABLE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    AGREEMENT_REQUIRED = "AGREEMENT_REQUIRED"
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    STREAM_CLOSED = "STREAM_CLOSED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    DEPENDENCY_FAILED = "DEPENDENCY_FAILED"
    CONTEXT_TOO_LARGE = "CONTEXT_TOO_LARGE"
    RATE_LIMITED = "RATE_LIMITED"
    NOT_FOUND = "NOT_FOUND"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    BOARD_ITEM_TAKEN = "BOARD_ITEM_TAKEN"
    ARTIFACT_GONE = "ARTIFACT_GONE"
    NOT_NAMED = "NOT_NAMED"

    def __str__(self) -> str:
        return self.value


RETRYABLE_CODES = frozenset(
    {
        ErrorCode.TRANSPORT_TIMEOUT,
        ErrorCode.AGENT_UNAVAILABLE,
        ErrorCode.AGENT_OVERLOADED,
        ErrorCode.INTERNAL_ERROR,
        ErrorCode.DEPENDENCY_FAILED,
        ErrorCode.RATE_LIMITED,
    }
)


class MeshError(Exception):
    """Something the mesh, a peer or the SDK refused or could not do.

    ``code`` is an :class:`ErrorCode` when the code is one this SDK knows, and
    the raw string otherwise (a newer peer may send a code this version has not
    heard of; that is still an error, not a crash).
    """

    def __init__(
        self,
        code: ErrorCode | str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        retryable: bool | None = None,
        retry_after_ms: int | None = None,
    ):
        super().__init__(message)
        try:
            self.code: ErrorCode | str = ErrorCode(code)
        except ValueError:
            self.code = str(code)
        self.message = message
        self.details = details
        self.retryable = retryable if retryable is not None else self.code in RETRYABLE_CODES
        self.retry_after_ms = retry_after_ms

    def to_error_object(self) -> dict[str, Any]:
        """The wire form (SPEC 5.1 ``error``). Absent fields are left out."""
        obj: dict[str, Any] = {
            "code": str(self.code),
            "message": self.message,
            "retryable": self.retryable,
            "retry_after_ms": self.retry_after_ms,
        }
        if self.details is not None:
            obj["details"] = self.details
        return obj

    @classmethod
    def from_error_object(cls, err: Any) -> "MeshError":
        if not isinstance(err, dict):
            return cls(ErrorCode.INTERNAL_ERROR, "the peer sent an error this SDK cannot read")
        return cls(
            str(err.get("code") or ErrorCode.INTERNAL_ERROR),
            str(err.get("message") or ""),
            details=err.get("details") if isinstance(err.get("details"), dict) else None,
            retryable=bool(err.get("retryable")) if "retryable" in err else None,
            retry_after_ms=err.get("retry_after_ms") if isinstance(err.get("retry_after_ms"), int) else None,
        )

    def __repr__(self) -> str:
        return f"MeshError({str(self.code)!r}, {self.message!r})"


class RejectedError(Exception):
    """Raise from a request handler to decline the work (task state ``rejected``).

    Different from failing: a rejection says this agent will not do the offering
    at all, so the requester should go elsewhere rather than retry.
    """

    def __init__(self, message: str = "The agent declined this request", *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details
