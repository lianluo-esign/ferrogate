"""The Python admin SDK, against a stub transport AND against a real socket.

Two layers, because they prove different things:

* ``StubTransportTests`` records the :class:`HttpRequest` the client built and
  hands back a chosen response — what goes on the wire, and what comes back
  off it;
* ``LoopbackServerTests`` runs the DEFAULT transport (``urllib``) against a
  ``ThreadingHTTPServer`` on 127.0.0.1, so the stdlib path a real caller uses
  is exercised rather than assumed. A stub-only suite would pass with a
  transport that never worked.

Nothing here needs a FerroGate deployment, an account or a credential. Run:

    python3 -m unittest discover -s sdks/python
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ferrogate_admin import (  # noqa: E402  (path set above)
    AdminClient,
    FerrogateApiError,
    FerrogateTransportError,
    HttpRequest,
    HttpResponse,
)

PROJECT_LIST = {
    "object": "list",
    "data": [{"id": "proj_1", "tenant_id": "t_1", "name": "Example", "slug": "example"}],
    "total": 1,
}


class RecordingTransport:
    """A transport that records every request and replays queued responses."""

    def __init__(self, *responses: HttpResponse) -> None:
        self.requests: list[HttpRequest] = []
        self._responses = list(responses)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError("transport called more times than it has responses")
        return self._responses.pop(0)

    @property
    def last(self) -> HttpRequest:
        return self.requests[-1]


def json_response(body: Any, status: int = 200, headers: dict[str, str] | None = None) -> HttpResponse:
    return HttpResponse(
        status=status,
        headers={"content-type": "application/json", **(headers or {})},
        text=json.dumps(body),
    )


class StubTransportTests(unittest.TestCase):
    def test_builds_url_with_path_params_and_query(self) -> None:
        transport = RecordingTransport(json_response(PROJECT_LIST))
        client = AdminClient("https://gateway.example.com/", token="t", transport=transport)

        client.get("/admin/v1/projects", query={"tenant_id": "t_1", "limit": 50})

        self.assertEqual(
            transport.last.url,
            "https://gateway.example.com/admin/v1/projects?tenant_id=t_1&limit=50",
        )
        self.assertEqual(transport.last.method, "GET")

    def test_percent_encodes_path_parameters(self) -> None:
        # A value containing "/" must not be able to reach another operation.
        transport = RecordingTransport(json_response({}))
        client = AdminClient("https://gateway.example.com", token="t", transport=transport)

        client.get("/admin/v1/plugins/{plugin_id}", path_params={"plugin_id": "a/../b"})

        self.assertEqual(
            transport.last.url, "https://gateway.example.com/admin/v1/plugins/a%2F..%2Fb"
        )

    def test_refuses_an_unfilled_path_parameter(self) -> None:
        client = AdminClient("https://gateway.example.com", token="t", transport=RecordingTransport())
        with self.assertRaises(ValueError):
            client.get("/admin/v1/plugins/{plugin_id}")

    def test_sends_the_bearer_credential(self) -> None:
        transport = RecordingTransport(json_response(PROJECT_LIST))
        AdminClient("https://x", token="fg_admin_token", transport=transport).get("/admin/v1/projects")

        self.assertEqual(transport.last.headers["authorization"], "Bearer fg_admin_token")
        self.assertNotIn("x-api-key", transport.last.headers)
        self.assertEqual(transport.last.headers["accept"], "application/json")

    def test_sends_the_api_key_credential(self) -> None:
        transport = RecordingTransport(json_response(PROJECT_LIST))
        AdminClient("https://x", api_key="fg_admin_key", transport=transport).get("/admin/v1/projects")

        self.assertEqual(transport.last.headers["x-api-key"], "fg_admin_key")
        self.assertNotIn("authorization", transport.last.headers)

    def test_refuses_both_credentials(self) -> None:
        with self.assertRaises(ValueError):
            AdminClient("https://x", token="t", api_key="k")

    def test_refuses_a_caller_api_key_when_token_is_configured(self) -> None:
        with self.assertRaises(ValueError):
            AdminClient("https://x", token="t", headers={"X-API-Key": "attacker-key"})

    def test_refuses_a_caller_authorization_when_api_key_is_configured(self) -> None:
        with self.assertRaises(ValueError):
            AdminClient("https://x", api_key="k", headers={"Authorization": "Bearer attacker"})

    def test_carries_the_tenant_and_caller_headers(self) -> None:
        transport = RecordingTransport(json_response(PROJECT_LIST))
        client = AdminClient(
            "https://x",
            token="t",
            tenant="tenant_42",
            headers={"X-Ferrogate-Action-Id": "act_7"},
            transport=transport,
        )

        client.get("/admin/v1/projects")

        self.assertEqual(transport.last.headers["x-ferrogate-tenant"], "tenant_42")
        # Header names are case-insensitive on the wire; this client normalizes
        # so a caller cannot accidentally send two spellings of one header.
        self.assertEqual(transport.last.headers["x-ferrogate-action-id"], "act_7")

    def test_serializes_a_json_body(self) -> None:
        transport = RecordingTransport(json_response({"id": "proj_2"}, status=201))
        client = AdminClient("https://x", token="t", transport=transport)

        created = client.post("/admin/v1/projects", body={"tenant_id": "t_1", "slug": "second"})

        self.assertEqual(created, {"id": "proj_2"})
        self.assertEqual(transport.last.headers["content-type"], "application/json")
        self.assertEqual(
            json.loads(transport.last.body or b"{}"), {"tenant_id": "t_1", "slug": "second"}
        )

    def test_renders_booleans_the_way_a_json_server_reads_them(self) -> None:
        transport = RecordingTransport(json_response(PROJECT_LIST))
        client = AdminClient("https://x", token="t", transport=transport)

        client.get("/admin/v1/projects", query={"enabled": True, "archived": False, "skip": None})

        # `str(True)` is "True", which no server parses as a boolean, and a
        # None must not become the string "None".
        self.assertIn("enabled=true", transport.last.url)
        self.assertIn("archived=false", transport.last.url)
        self.assertNotIn("skip", transport.last.url)

    def test_serves_the_control_v1_alias(self) -> None:
        transport = RecordingTransport(json_response(PROJECT_LIST))
        client = AdminClient("https://x", token="t", prefix="/control/v1", transport=transport)

        client.get("/admin/v1/projects", query={"limit": 10})

        self.assertEqual(transport.last.url, "https://x/control/v1/projects?limit=10")

    def test_alias_requires_an_admin_v1_path_segment_boundary(self) -> None:
        transport = RecordingTransport(json_response(PROJECT_LIST))
        client = AdminClient("https://x", token="t", prefix="/control/v1", transport=transport)

        client.get("/admin/v10/projects")

        self.assertEqual(transport.last.url, "https://x/admin/v10/projects")

    def test_decodes_the_error_envelope(self) -> None:
        transport = RecordingTransport(
            json_response(
                {
                    "error": {
                        "message": "credential lacks admin.write",
                        "type": "ferrogate_error",
                        "code": "scope_denied",
                        "request_id": "fg-body-id",
                        "required_scope": "admin.write",
                    }
                },
                status=403,
                headers={"x-request-id": "fg-header-id", "x-trace-id": "trace-9"},
            )
        )
        client = AdminClient("https://x", token="t", transport=transport)

        with self.assertRaises(FerrogateApiError) as raised:
            client.get("/admin/v1/projects")

        error = raised.exception
        self.assertEqual(error.status, 403)
        self.assertEqual(error.code, "scope_denied")
        self.assertEqual(error.message, "credential lacks admin.write")
        # The HEADER wins over the body: an edge that rewrites the id is the
        # authority on what the operator will find in the log.
        self.assertEqual(error.request_id, "fg-header-id")
        self.assertEqual(error.trace_id, "trace-9")
        # Everything beyond the four envelope members survives.
        self.assertEqual(error.details, {"required_scope": "admin.write"})

    def test_falls_back_to_the_envelope_request_id(self) -> None:
        transport = RecordingTransport(
            json_response(
                {"error": {"message": "nope", "code": "not_found", "request_id": "fg-body-only"}},
                status=404,
            )
        )
        with self.assertRaises(FerrogateApiError) as raised:
            AdminClient("https://x", token="t", transport=transport).get("/admin/v1/projects")

        self.assertEqual(raised.exception.request_id, "fg-body-only")

    def test_types_a_non_json_error_body(self) -> None:
        transport = RecordingTransport(
            HttpResponse(
                status=502,
                headers={"content-type": "text/html"},
                text="<html><title>502 Bad Gateway</title></html>",
            )
        )
        with self.assertRaises(FerrogateApiError) as raised:
            AdminClient("https://x", token="t", transport=transport).get("/admin/v1/projects")

        error = raised.exception
        self.assertEqual(error.status, 502)
        # No code in the body ⇒ the status-derived fallback, so a caller can
        # still switch on `code` for a response FerroGate never wrote.
        self.assertEqual(error.code, "server_error")
        self.assertIn("502 Bad Gateway", error.message)

    def test_types_an_empty_error_body_and_reads_retry_after(self) -> None:
        transport = RecordingTransport(HttpResponse(429, {"retry-after": "12"}, ""))
        with self.assertRaises(FerrogateApiError) as raised:
            AdminClient("https://x", token="t", transport=transport).get("/admin/v1/projects")

        error = raised.exception
        self.assertEqual(error.code, "retryable_error")
        self.assertEqual(error.message, "request failed with HTTP 429")
        self.assertEqual(error.retry_after_seconds, 12)

    def test_returns_none_for_204(self) -> None:
        transport = RecordingTransport(HttpResponse(204, {}, ""))
        client = AdminClient("https://x", token="t", transport=transport)

        self.assertIsNone(
            client.delete("/admin/v1/plugins/{plugin_id}", path_params={"plugin_id": "p1"})
        )
        self.assertEqual(transport.last.method, "DELETE")

    def test_a_2xx_that_is_not_json_is_an_api_error_not_a_decode_error(self) -> None:
        transport = RecordingTransport(HttpResponse(200, {"content-type": "text/html"}, "<html/>"))
        with self.assertRaises(FerrogateApiError):
            AdminClient("https://x", token="t", transport=transport).get("/admin/v1/projects")


class _Handler(BaseHTTPRequestHandler):
    """Answers whatever the test put on the server object."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: Any) -> None:  # keep the test output clean
        return

    def _respond(self) -> None:
        server: Any = self.server
        server.seen.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": {key.lower(): value for key, value in self.headers.items()},
                "body": self.rfile.read(int(self.headers.get("content-length") or 0)),
            }
        )
        payload = json.dumps(server.body).encode("utf-8")
        self.send_response(server.status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        for key, value in server.extra_headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _respond
    do_POST = _respond
    do_DELETE = _respond


class LoopbackServerTests(unittest.TestCase):
    """The DEFAULT (urllib) transport, against a real socket on 127.0.0.1."""

    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.seen = []  # type: ignore[attr-defined]
        self.server.body = PROJECT_LIST  # type: ignore[attr-defined]
        self.server.status = 200  # type: ignore[attr-defined]
        self.server.extra_headers = {}  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_round_trips_a_real_request(self) -> None:
        client = AdminClient(self.base_url, token="fg_admin_token", tenant="tenant_42")

        page = client.get("/admin/v1/projects", query={"limit": 2})

        self.assertEqual(page["data"][0]["slug"], "example")
        seen = self.server.seen[0]  # type: ignore[attr-defined]
        self.assertEqual(seen["path"], "/admin/v1/projects?limit=2")
        self.assertEqual(seen["headers"]["authorization"], "Bearer fg_admin_token")
        self.assertEqual(seen["headers"]["x-ferrogate-tenant"], "tenant_42")

    def test_posts_a_body_over_the_socket(self) -> None:
        self.server.status = 201  # type: ignore[attr-defined]
        self.server.body = {"id": "proj_2"}  # type: ignore[attr-defined]
        client = AdminClient(self.base_url, token="t")

        created = client.post("/admin/v1/projects", body={"slug": "second"})

        self.assertEqual(created, {"id": "proj_2"})
        seen = self.server.seen[0]  # type: ignore[attr-defined]
        self.assertEqual(json.loads(seen["body"]), {"slug": "second"})
        self.assertEqual(seen["headers"]["content-type"], "application/json")

    def test_raises_the_typed_error_for_a_real_non_2xx(self) -> None:
        # urllib raises HTTPError for a 4xx; the transport must turn that back
        # into an ordinary response so the ONE classifier sees it.
        self.server.status = 403  # type: ignore[attr-defined]
        self.server.body = {  # type: ignore[attr-defined]
            "error": {
                "message": "credential lacks admin.write",
                "type": "ferrogate_error",
                "code": "scope_denied",
                "request_id": "fg-1",
            }
        }
        client = AdminClient(self.base_url, token="t")

        with self.assertRaises(FerrogateApiError) as raised:
            client.get("/admin/v1/projects")

        self.assertEqual(raised.exception.code, "scope_denied")
        self.assertEqual(raised.exception.status, 403)

    def test_a_refused_connection_is_a_transport_error(self) -> None:
        # Shut the server down first, so the port is closed.
        self.server.shutdown()
        self.server.server_close()
        client = AdminClient(self.base_url, token="t", timeout=2)

        with self.assertRaises(FerrogateTransportError) as raised:
            client.get("/admin/v1/projects")

        self.assertIn("/admin/v1/projects", raised.exception.url)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
