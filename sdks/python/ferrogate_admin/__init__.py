"""``ferrogate_admin`` — the thin Python client for the FerroGate Control Plane
API (issue #675).

Standard library only. See ``client.py`` for what this deliberately does not
do (generated models, pagination, retries) and why.

Run its tests with::

    python3 -m unittest discover -s sdks/python
"""

from .client import (
    CONTROL_PLANE_PREFIXES,
    DEFAULT_TIMEOUT_SECONDS,
    AdminClient,
    HttpRequest,
    HttpResponse,
    Transport,
    urllib_transport,
)
from .api import ADMIN_OPERATION_IDS, OPENAPI_OPERATION_COUNT, OPERATIONS, Operation
from .errors import (
    ERROR_ENVELOPE_FIELDS,
    FerrogateApiError,
    FerrogateError,
    FerrogateTransportError,
    api_error_from,
    default_code_for_status,
)

__all__ = [
    "CONTROL_PLANE_PREFIXES",
    "DEFAULT_TIMEOUT_SECONDS",
    "ERROR_ENVELOPE_FIELDS",
    "AdminClient",
    "ADMIN_OPERATION_IDS",
    "FerrogateApiError",
    "FerrogateError",
    "FerrogateTransportError",
    "HttpRequest",
    "HttpResponse",
    "OPENAPI_OPERATION_COUNT",
    "OPERATIONS",
    "Operation",
    "Transport",
    "api_error_from",
    "default_code_for_status",
    "urllib_transport",
]
