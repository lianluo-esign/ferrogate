"""Typed failures of the FerroGate Control Plane API.

Every FerroGate control-plane error is one envelope, written by one function
(``writeJsonError``, ``apps/control-plane/src/middleware/errors.ts``)::

    {"error": {"message": "...", "type": "ferrogate_error",
               "code": "scope_denied", "request_id": "fg-..."}}

so decoding it belongs in the client, not in every caller. ``code`` is the
stable machine-readable member — application code switches on it, never on the
message — and ``request_id`` is what an operator quotes in a bug report.

The rules below are the SAME rules the TypeScript SDK and the FerroGate CLI
apply (``sdks/typescript/src/errors.ts``, ``apps/cli/src/ports.ts``), because
one request must not produce three different errors depending on which client
issued it:

* a body that is not the envelope (an HTML 502 from a load balancer, an empty
  504) still produces a typed error, never a ``JSONDecodeError``;
* the correlation id is read from ``x-request-id`` first and from the
  envelope's ``request_id`` second, so it survives an edge that strips either;
* every extra member of the ``error`` object is preserved in ``details``.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

#: The four members every FerroGate error object carries.
ERROR_ENVELOPE_FIELDS = ("message", "type", "code", "request_id")


class FerrogateError(Exception):
    """Base class, so one ``except`` catches every failure of this client."""


class FerrogateApiError(FerrogateError):
    """A non-2xx answer from the control plane."""

    def __init__(
        self,
        *,
        status: int,
        code: str,
        message: str,
        request_id: str | None = None,
        trace_id: str | None = None,
        retry_after_seconds: int | None = None,
        details: Mapping[str, Any] | None = None,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id
        self.trace_id = trace_id
        self.retry_after_seconds = retry_after_seconds
        self.details: Mapping[str, Any] = dict(details or {})
        self.body = body
        self.headers: Mapping[str, str] = dict(headers or {})

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"FerrogateApiError(status={self.status!r}, code={self.code!r}, "
            f"request_id={self.request_id!r}, message={self.message!r})"
        )


class FerrogateTransportError(FerrogateError):
    """A request that never produced a response (DNS, TLS, timeout, refused)."""

    def __init__(self, url: str, message: str) -> None:
        super().__init__(message)
        self.url = url


def default_code_for_status(status: int) -> str:
    """Fallback ``code`` for a body that carried none.

    The same buckets the CLI exits on, so a caller can switch on ``code`` even
    when a proxy answered instead of FerroGate.
    """
    if status in (401, 403):
        return "unauthorized"
    if status in (404, 409):
        return "not_found"
    if status in (400, 422):
        return "invalid_request"
    if status in (408, 429, 503, 504):
        return "retryable_error"
    if status >= 500:
        return "server_error"
    return "error"


def _as_object(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _integer_header(headers: Mapping[str, str], name: str) -> int | None:
    raw = headers.get(name)
    if raw is None:
        return None
    raw = raw.strip()
    return int(raw) if raw.isdigit() else None


def api_error_from(status: int, headers: Mapping[str, str], text: str) -> FerrogateApiError:
    """Build the typed error for a non-2xx response.

    Takes ``text`` rather than a response object so it is pure and testable.
    ``headers`` must be case-insensitive (``LowercaseHeaders`` in ``client``).
    """
    try:
        body: Any = json.loads(text) if text else None
    except ValueError:
        # NOT an error: a 502 from a load balancer is an HTML page, and the
        # caller still gets a typed exception with the right status.
        body = text

    error_object = _as_object((_as_object(body) or {}).get("error"))
    envelope_message = (error_object or {}).get("message")
    envelope_code = (error_object or {}).get("code")
    envelope_request_id = (error_object or {}).get("request_id")

    request_id = headers.get("x-request-id") or (
        envelope_request_id if isinstance(envelope_request_id, str) else None
    )
    details = {
        key: value
        for key, value in (error_object or {}).items()
        if key not in ERROR_ENVELOPE_FIELDS
    }

    stripped = text.strip()
    if isinstance(envelope_message, str):
        message = envelope_message
    elif stripped == "":
        message = f"request failed with HTTP {status}"
    else:
        message = stripped

    return FerrogateApiError(
        status=status,
        code=envelope_code if isinstance(envelope_code, str) else default_code_for_status(status),
        message=message,
        request_id=request_id,
        trace_id=headers.get("x-trace-id"),
        retry_after_seconds=_integer_header(headers, "retry-after"),
        details=details,
        body=body,
        headers=headers,
    )
