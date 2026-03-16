"""
Proxy HTTP integration tests: spin up a mock upstream and the real proxy,
then verify end-to-end HTTP behaviour (forwarding, redaction, headers, errors,
streaming, concurrency, passthrough, etc.).

Every test allocates dynamic ports (port 0) so there are no conflicts.
"""
from __future__ import annotations

import json
import threading
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers — mock upstream server
# ---------------------------------------------------------------------------


class _UpstreamHandler(BaseHTTPRequestHandler):
    """Captures the last request and replies with a configurable response."""

    # Class-level state shared across requests (set before each test)
    last_method: str | None = None
    last_path: str | None = None
    last_headers: dict | None = None
    last_body: bytes | None = None

    # Response configuration
    response_status: int = 200
    response_body: bytes = b'{"ok": true}'
    response_headers: dict = {}

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length)

        cls = self.__class__
        cls.last_method = "POST"
        cls.last_path = self.path
        cls.last_headers = dict(self.headers)
        cls.last_body = body

        self.send_response(cls.response_status)
        for k, v in cls.response_headers.items():
            self.send_header(k, v)
        if "content-type" not in {k.lower() for k in cls.response_headers}:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(cls.response_body)))
        self.end_headers()
        self.wfile.write(cls.response_body)

    def log_message(self, fmt, *args):
        pass


def _reset_upstream(handler_cls):
    handler_cls.last_method = None
    handler_cls.last_path = None
    handler_cls.last_headers = None
    handler_cls.last_body = None
    handler_cls.response_status = 200
    handler_cls.response_body = b'{"ok": true}'
    handler_cls.response_headers = {}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def upstream_server():
    """Start a mock upstream HTTP server on a dynamic port."""
    _reset_upstream(_UpstreamHandler)
    server = HTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server, port
    server.shutdown()


@pytest.fixture()
def proxy_server(upstream_server, tmp_path):
    """Start the real proxy pointed at the mock upstream, on a dynamic port."""
    _, upstream_port = upstream_server
    upstream_url = f"http://127.0.0.1:{upstream_port}"

    from engine.config import Config
    from engine.allowlist import Allowlist
    from proxy.server import ProxyHandler, _build_components

    config = Config(openai_upstream=upstream_url)
    anthropic_filter, openai_filter = _build_components(config, Allowlist())

    ProxyHandler._config = config
    ProxyHandler._anthropic_filter = anthropic_filter
    ProxyHandler._openai_filter = openai_filter

    server = HTTPServer(("127.0.0.1", 0), ProxyHandler)
    proxy_port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    with patch("proxy.server.ANTHROPIC_UPSTREAM", upstream_url):
        yield server, proxy_port, upstream_url

    server.shutdown()


def _post(port: int, path: str, body: bytes | None = None,
          headers: dict | None = None) -> tuple[int, dict, bytes]:
    """Send a POST request and return (status, headers_dict, body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    if body is None:
        body = b""
    conn.request("POST", path, body=body, headers=hdrs)
    resp = conn.getresponse()
    resp_body = resp.read()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, resp_headers, resp_body


# ---------------------------------------------------------------------------
# 1. Clean request forwarded unchanged
# ---------------------------------------------------------------------------


class TestCleanRequestForwarded:
    def test_clean_payload_unchanged(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        payload = {"messages": [{"role": "user", "content": "Hello, world!"}]}
        body = json.dumps(payload).encode()

        status, _, _ = _post(proxy_port, "/v1/messages", body)

        assert status == 200
        upstream_body = json.loads(_UpstreamHandler.last_body)
        assert upstream_body == payload
        assert _UpstreamHandler.last_path == "/v1/messages"


# ---------------------------------------------------------------------------
# 2. Request with secret is redacted
# ---------------------------------------------------------------------------


class TestSecretRedacted:
    def test_api_key_redacted_before_forwarding(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        payload = {
            "messages": [
                {"role": "user", "content": "My key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}
            ]
        }
        body = json.dumps(payload).encode()

        status, _, _ = _post(proxy_port, "/v1/messages", body)

        assert status == 200
        upstream_body = json.loads(_UpstreamHandler.last_body)
        content = upstream_body["messages"][0]["content"]
        assert "sk-ant-api03" not in content
        assert "[REDACTED:api_key]" in content


# ---------------------------------------------------------------------------
# 3. OpenAI routing
# ---------------------------------------------------------------------------


class TestOpenAIRouting:
    def test_chat_completions_forwarded(self, proxy_server, upstream_server):
        _, proxy_port, upstream_url = proxy_server
        payload = {"messages": [{"role": "user", "content": "hi"}]}
        body = json.dumps(payload).encode()

        status, _, _ = _post(proxy_port, "/v1/chat/completions", body)

        assert status == 200
        assert _UpstreamHandler.last_path == "/v1/chat/completions"

    def test_openai_secret_redacted(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        payload = {
            "messages": [
                {"role": "user", "content": "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}
            ]
        }
        body = json.dumps(payload).encode()

        status, _, _ = _post(proxy_port, "/v1/chat/completions", body)

        assert status == 200
        upstream_body = json.loads(_UpstreamHandler.last_body)
        assert "[REDACTED:api_key]" in upstream_body["messages"][0]["content"]


# ---------------------------------------------------------------------------
# 4. Hop-by-hop headers stripped
# ---------------------------------------------------------------------------


class TestHopByHopHeaders:
    def test_connection_and_transfer_encoding_stripped(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        payload = {"messages": [{"role": "user", "content": "hello"}]}
        body = json.dumps(payload).encode()
        extra_headers = {
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
            "X-Custom": "should-pass",
        }

        _post(proxy_port, "/v1/messages", body, headers=extra_headers)

        fwd = _UpstreamHandler.last_headers
        fwd_lower = {k.lower(): v for k, v in fwd.items()}
        # Client's "keep-alive" must not pass through (urllib may add its own
        # "Connection: close" which is fine — that's the transport layer)
        assert fwd_lower.get("connection") != "keep-alive"
        assert "transfer-encoding" not in fwd_lower
        assert fwd_lower.get("x-custom") == "should-pass"


# ---------------------------------------------------------------------------
# 5. Host header replaced
# ---------------------------------------------------------------------------


class TestHostHeaderReplaced:
    def test_host_header_not_forwarded(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        payload = {"messages": [{"role": "user", "content": "hi"}]}
        body = json.dumps(payload).encode()

        _post(proxy_port, "/v1/messages", body)

        fwd = _UpstreamHandler.last_headers
        fwd_lower = {k.lower(): v for k, v in fwd.items()}
        host_val = fwd_lower.get("host", "")
        assert str(proxy_port) not in host_val


# ---------------------------------------------------------------------------
# 6. Content-Length updated after redaction
# ---------------------------------------------------------------------------


class TestContentLengthUpdated:
    def test_content_length_matches_redacted_body(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        payload = {
            "messages": [
                {"role": "user", "content": "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}
            ]
        }
        body = json.dumps(payload).encode()

        _post(proxy_port, "/v1/messages", body)

        fwd = _UpstreamHandler.last_headers
        fwd_lower = {k.lower(): v for k, v in fwd.items()}
        declared = int(fwd_lower["content-length"])
        actual = len(_UpstreamHandler.last_body)
        assert declared == actual


# ---------------------------------------------------------------------------
# 7. Upstream 4xx/5xx errors transparently proxied
# ---------------------------------------------------------------------------


class TestUpstreamErrors:
    @pytest.mark.parametrize("error_code", [400, 401, 403, 404, 429, 500, 502, 503])
    def test_error_status_forwarded(self, proxy_server, upstream_server, error_code):
        _, proxy_port, _ = proxy_server
        _UpstreamHandler.response_status = error_code
        _UpstreamHandler.response_body = json.dumps({"error": "nope"}).encode()

        payload = {"messages": [{"role": "user", "content": "hi"}]}
        body = json.dumps(payload).encode()

        status, _, resp_body = _post(proxy_port, "/v1/messages", body)

        assert status == error_code
        assert json.loads(resp_body) == {"error": "nope"}


# ---------------------------------------------------------------------------
# 8. Filter exception (malformed JSON) doesn't crash proxy
# ---------------------------------------------------------------------------


class TestMalformedJSON:
    def test_non_json_body_forwarded_as_is(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        bad_body = b"this is not json {{{}"

        status, _, _ = _post(proxy_port, "/v1/messages", bad_body)

        assert status == 200
        assert _UpstreamHandler.last_body == bad_body


# ---------------------------------------------------------------------------
# 9. Enabled=false passthrough
# ---------------------------------------------------------------------------


class TestEnabledFalsePassthrough:
    def test_secret_not_redacted_when_disabled(self, proxy_server, upstream_server, tmp_path):
        _, proxy_port, _ = proxy_server

        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"enabled": False}))

        payload = {
            "messages": [
                {"role": "user", "content": "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}
            ]
        }
        body = json.dumps(payload).encode()

        with patch("proxy.server.CONFIG_PATH", cfg):
            status, _, _ = _post(proxy_port, "/v1/messages", body)

        assert status == 200
        upstream_body = json.loads(_UpstreamHandler.last_body)
        content = upstream_body["messages"][0]["content"]
        assert "sk-ant-api03-abcdefghijklmnopqrstuvwxyz" in content
        assert "[REDACTED" not in content


# ---------------------------------------------------------------------------
# 10. Streaming response forwarded (response > 4096 bytes)
# ---------------------------------------------------------------------------


class _StreamingUpstreamHandler(BaseHTTPRequestHandler):
    """Returns a large response body that exceeds 4096 bytes."""

    last_body: bytes | None = None

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        self.__class__.last_body = self.rfile.read(length)

        full_body = b"x" * 10_000

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(full_body)))
        self.end_headers()
        self.wfile.write(full_body)

    def log_message(self, fmt, *args):
        pass


class TestStreamingResponse:
    def test_large_response_fully_received(self):
        """Verify that a response larger than 4096 bytes is forwarded completely."""
        from engine.config import Config
        from engine.allowlist import Allowlist
        from proxy.server import ProxyHandler, _build_components

        upstream = HTTPServer(("127.0.0.1", 0), _StreamingUpstreamHandler)
        upstream_port = upstream.server_address[1]
        upstream_url = f"http://127.0.0.1:{upstream_port}"
        t_up = threading.Thread(target=upstream.serve_forever, daemon=True)
        t_up.start()

        config = Config(openai_upstream=upstream_url)
        anthropic_filter, openai_filter = _build_components(config, Allowlist())

        ProxyHandler._config = config
        ProxyHandler._anthropic_filter = anthropic_filter
        ProxyHandler._openai_filter = openai_filter

        proxy = HTTPServer(("127.0.0.1", 0), ProxyHandler)
        proxy_port = proxy.server_address[1]
        t_pr = threading.Thread(target=proxy.serve_forever, daemon=True)
        t_pr.start()

        try:
            with patch("proxy.server.ANTHROPIC_UPSTREAM", upstream_url):
                payload = {"messages": [{"role": "user", "content": "hi"}]}
                body = json.dumps(payload).encode()
                status, _, resp_body = _post(proxy_port, "/v1/messages", body)

            assert status == 200
            assert len(resp_body) == 10_000
            assert resp_body == b"x" * 10_000
        finally:
            proxy.shutdown()
            upstream.shutdown()


# ---------------------------------------------------------------------------
# 11. Concurrent requests
# ---------------------------------------------------------------------------


class TestConcurrentRequests:
    def test_ten_simultaneous_requests(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        results = [None] * 10
        errors = []

        def _do_request(idx):
            try:
                payload = {"messages": [{"role": "user", "content": f"msg-{idx}"}]}
                body = json.dumps(payload).encode()
                status, _, _ = _post(proxy_port, "/v1/messages", body)
                results[idx] = status
            except Exception as exc:
                errors.append((idx, exc))

        threads = [threading.Thread(target=_do_request, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert not errors, f"Errors in concurrent requests: {errors}"
        assert all(s == 200 for s in results), f"Not all 200: {results}"


# ---------------------------------------------------------------------------
# 12. Request with no Content-Length or Content-Length=0
# ---------------------------------------------------------------------------


class TestNoContentLength:
    def test_content_length_zero(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        status, _, _ = _post(proxy_port, "/v1/messages", b"",
                             headers={"Content-Length": "0"})
        assert status == 200

    def test_empty_body_still_forwarded(self, proxy_server, upstream_server):
        _, proxy_port, _ = proxy_server
        status, _, _ = _post(proxy_port, "/v1/messages", b"")
        assert status == 200
        assert _UpstreamHandler.last_body == b""
