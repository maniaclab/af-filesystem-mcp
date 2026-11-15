"""Observability contract (af-mcp-platform docs/mcp-design.md L1-L3, U7).

The broker-mode tests run the real ASGI app against a real local JWKS
endpoint and real signed broker tokens: nothing in the request path is
mocked, so a request id that survives to the tool-call line really crossed
the HTTP edge, the SDK's auth middleware and the tool dispatcher.
"""

from __future__ import annotations

import io
import json
import logging
import os
import pwd
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from af_filesystem_mcp.observability import (
    JsonFormatter,
    RequestLogMiddleware,
    configure_logging,
    request_id_var,
)
from af_filesystem_mcp.server import _make_broker_app

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

AUDIENCE = "af-filesystem-mcp"
ISSUER = "https://broker.example.com"
JSON_RPC_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


class JwksServer:
    """A real HTTP endpoint publishing a JWKS and counting how often it is fetched."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.fetches = 0
        self.published_kid = "kid-1"
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outer.fetches += 1
                jwk = json.loads(
                    jwt.algorithms.RSAAlgorithm.to_jwk(outer.key.public_key())
                )
                jwk.update(kid=outer.published_kid, alg="RS256", use="sig")
                body = json.dumps({"keys": [jwk]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self._httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._httpd.server_port}/.well-known/jwks.json"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def token(self, kid: str = "kid-1", sub: str = "user-sub") -> str:
        user = pwd.getpwuid(os.getuid())
        return jwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": sub,
                "jti": "jti-1",
                "exp": int(time.time()) + 300,
                "uid": user.pw_uid,
                "gid": user.pw_gid,
                "unixname": user.pw_name,
            },
            self.key,
            algorithm="RS256",
            headers={"kid": kid},
        )


@pytest.fixture
def jwks() -> Iterator[JwksServer]:
    server = JwksServer()
    yield server
    server.close()


@pytest.fixture
def log_lines() -> Iterator[io.StringIO]:
    """Route every log record to a buffer as JSON, restoring the root logger after."""
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    buffer = io.StringIO()
    configure_logging("info", stream=buffer)
    # The test client's own request lines are written outside any request.
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    yield buffer
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def parsed(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line]


@pytest.fixture
def client(
    jwks: JwksServer, tmp_path: Path, log_lines: io.StringIO
) -> Iterator[TestClient]:
    unixname = pwd.getpwuid(os.getuid()).pw_name
    (tmp_path / "home" / unixname).mkdir(parents=True)
    (tmp_path / "data" / unixname).mkdir(parents=True)
    app = _make_broker_app(
        jwks_url=jwks.url,
        issuer=ISSUER,
        audience=AUDIENCE,
        home_root=tmp_path / "home",
        data_root=tmp_path / "data",
        timeout_seconds=10.0,
        max_concurrent_calls_per_user=4,
        resource_url="http://localhost:8000",
        host="127.0.0.1",
    )
    with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
        # Drop the lifespan's startup lines: they belong to no request.
        log_lines.seek(0)
        log_lines.truncate()
        yield test_client


def call_fs_list(client: TestClient, token: str, request_id: str | None = "abc") -> Any:
    headers = {**JSON_RPC_HEADERS, "Authorization": f"Bearer {token}"}
    if request_id is not None:
        headers["X-Request-ID"] = request_id
    return client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "fs_list", "arguments": {"root": "home", "path": ""}},
        },
        headers=headers,
    )


class TestJsonFormatter:
    def test_standard_fields_and_request_id(self) -> None:
        record = logging.LogRecord(
            "lg", logging.WARNING, __file__, 1, "evt", None, None
        )
        record.fields = {"tool": "fs_list", "duration_ms": 1.5}
        reset = request_id_var.set("rid-7")
        try:
            entry = json.loads(JsonFormatter().format(record))
        finally:
            request_id_var.reset(reset)
        assert entry["level"] == "warning"
        assert entry["logger"] == "lg"
        assert entry["event"] == "evt"
        assert entry["request_id"] == "rid-7"
        assert entry["tool"] == "fs_list"
        assert entry["timestamp"].endswith("+00:00")


class TestRequestId:
    def test_every_line_of_a_request_carries_the_brokers_id(
        self, client: TestClient, jwks: JwksServer, log_lines: io.StringIO
    ) -> None:
        resp = call_fs_list(client, jwks.token(), request_id="abc")
        assert resp.status_code == 200
        lines = parsed(log_lines)
        assert {"tool.call", "http.request"} <= {line["event"] for line in lines}
        assert all(line.get("request_id") == "abc" for line in lines)

    def test_an_id_is_generated_when_the_header_is_absent(
        self, client: TestClient, jwks: JwksServer, log_lines: io.StringIO
    ) -> None:
        call_fs_list(client, jwks.token(), request_id=None)
        ids = {line["request_id"] for line in parsed(log_lines)}
        assert len(ids) == 1
        assert ids.pop()

    def test_an_overlong_id_is_truncated(
        self, client: TestClient, jwks: JwksServer, log_lines: io.StringIO
    ) -> None:
        call_fs_list(client, jwks.token(), request_id="x" * 500)
        assert {len(line["request_id"]) for line in parsed(log_lines)} == {128}


class TestToolCallLine:
    def test_carries_the_contract_fields(
        self, client: TestClient, jwks: JwksServer, log_lines: io.StringIO
    ) -> None:
        call_fs_list(client, jwks.token(sub="the-sub"))
        (line,) = [x for x in parsed(log_lines) if x["event"] == "tool.call"]
        assert line["tool"] == "fs_list"
        assert line["subject"] == "the-sub"
        assert line["outcome"] == "ok"
        assert line["duration_ms"] >= 0

    def test_a_tool_error_result_is_outcome_error(
        self, client: TestClient, jwks: JwksServer, log_lines: io.StringIO
    ) -> None:
        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "fs_list",
                    "arguments": {"root": "home", "path": "no-such-dir"},
                },
            },
            headers={**JSON_RPC_HEADERS, "Authorization": f"Bearer {jwks.token()}"},
        )
        # The stateless transport answers as a server-sent event.
        (data,) = [x for x in resp.text.splitlines() if x.startswith("data: ")]
        assert json.loads(data.removeprefix("data: "))["result"]["isError"] is True
        (line,) = [x for x in parsed(log_lines) if x["event"] == "tool.call"]
        assert line["outcome"] == "error"

    def test_never_logs_the_token_or_arguments(
        self, client: TestClient, jwks: JwksServer, log_lines: io.StringIO
    ) -> None:
        token = jwks.token()
        call_fs_list(client, token)
        assert token not in log_lines.getvalue()


class TestProbeNoise:
    def test_successful_healthz_writes_no_access_line(
        self, client: TestClient, log_lines: io.StringIO
    ) -> None:
        assert client.get("/healthz").status_code == 200
        assert not [x for x in parsed(log_lines) if x.get("path") == "/healthz"]

    def test_failing_probe_is_logged(self, log_lines: io.StringIO) -> None:
        async def failing(_request: Any) -> PlainTextResponse:
            return PlainTextResponse("down", status_code=503)

        app = Starlette(routes=[Route("/healthz", failing)])
        app.add_middleware(RequestLogMiddleware)
        TestClient(app).get("/healthz")
        (line,) = parsed(log_lines)
        assert (line["path"], line["status"]) == ("/healthz", 503)

    def test_other_requests_keep_their_access_line(
        self, client: TestClient, log_lines: io.StringIO
    ) -> None:
        resp = client.post("/mcp", json={})
        (line,) = [x for x in parsed(log_lines) if x["event"] == "http.request"]
        assert (line["path"], line["status"]) == ("/mcp", resp.status_code)


class TestJwksCache:
    def test_repeated_requests_fetch_the_jwks_once(
        self, client: TestClient, jwks: JwksServer
    ) -> None:
        for _ in range(5):
            assert call_fs_list(client, jwks.token()).status_code == 200
        assert jwks.fetches == 1
