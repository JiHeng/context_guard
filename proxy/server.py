"""
HTTP proxy server: intercepts POST /v1/messages (Anthropic) and
POST /v1/chat/completions (OpenAI), redacts PII/secrets, then forwards upstream.
"""
from __future__ import annotations

import json
import os
import signal
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from engine.audit import AuditLogger
from engine.allowlist import Allowlist
from engine.config import Config, load as load_config
from engine.redactor import Redactor
from engine.rules import build_rules
from proxy.message_filter import MessageFilter
from proxy.openai_filter import OpenAIFilter

ANTHROPIC_UPSTREAM = "https://api.anthropic.com"
DEFAULT_PORT = 8765
PID_PATH = Path.home() / ".context_guard" / "proxy.pid"
CONFIG_PATH = Path.home() / ".context_guard" / "config.json"
_LOCAL_CONFIG = Path(__file__).parent.parent / "config.json"


def _is_enabled() -> bool:
    """Check the 'enabled' flag in config.json (default True)."""
    for p in (CONFIG_PATH, _LOCAL_CONFIG):
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return bool(data.get("enabled", True))
            except (json.JSONDecodeError, OSError):
                return True
    return True


# Headers that must not be forwarded as-is
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}


def _build_components(config: Config, allowlist: Allowlist):
    rules = build_rules(config)
    redactor = Redactor(rules=rules, allowlist=allowlist)
    return (
        MessageFilter(redactor=redactor),
        OpenAIFilter(redactor=redactor),
    )


class ProxyHandler(BaseHTTPRequestHandler):
    # Set by start() before server creation
    _config: Config = None
    _anthropic_filter: MessageFilter = None
    _openai_filter: OpenAIFilter = None

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length)

        is_openai = self.path.startswith("/v1/chat/completions")

        if _is_enabled():
            try:
                payload = json.loads(body)
                if is_openai:
                    filtered_payload, categories, diffs = self.__class__._openai_filter.process(payload)
                else:
                    filtered_payload, categories, diffs = self.__class__._anthropic_filter.process(payload)
                AuditLogger().log("api_request", categories)
                body = json.dumps(filtered_payload).encode("utf-8")
            except Exception as exc:
                print(f"[context_guard] filter error: {exc}", file=sys.stderr)

        # Determine upstream
        if is_openai:
            upstream = self.__class__._config.openai_upstream.rstrip("/")
        else:
            upstream = ANTHROPIC_UPSTREAM

        # Build forwarding headers
        forward_headers = {}
        for k, v in self.headers.items():
            if k.lower() in _HOP_BY_HOP or k.lower() == "host":
                continue
            forward_headers[k] = v
        forward_headers["content-length"] = str(len(body))
        forward_headers["content-type"] = "application/json"

        url = f"{upstream}{self.path}"
        req = urllib.request.Request(
            url, data=body, headers=forward_headers, method="POST"
        )

        try:
            resp = urllib.request.urlopen(req, timeout=300)
            status = resp.status
            resp_headers = resp.headers
            resp_body = resp
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_headers = exc.headers
            resp_body = exc

        self.send_response(status)
        for h, v in resp_headers.items():
            if h.lower() in _HOP_BY_HOP:
                continue
            self.send_header(h, v)
        self.end_headers()

        try:
            while True:
                chunk = resp_body.read(4096)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, fmt, *args):
        print(f"[context_guard] {self.command} {self.path} → {args[1]}", file=sys.stderr)


def _write_pid():
    PID_PATH.parent.mkdir(parents=True, exist_ok=True)
    PID_PATH.write_text(str(os.getpid()))


def _delete_pid():
    try:
        PID_PATH.unlink()
    except FileNotFoundError:
        pass


def start(port: int = DEFAULT_PORT, config: Config | None = None, allowlist: Allowlist | None = None):
    if config is None:
        config = load_config()
    if allowlist is None:
        allowlist = Allowlist()

    anthropic_filter, openai_filter = _build_components(config, allowlist)
    ProxyHandler._config = config
    ProxyHandler._anthropic_filter = anthropic_filter
    ProxyHandler._openai_filter = openai_filter

    rules = build_rules(config)
    n_rules = len(rules)
    n_disabled = len(config.disabled_rules)
    n_allow = len(allowlist)

    for w in config.warnings:
        print(f"[context_guard] ⚠ Config warning: {w}", file=sys.stderr)

    def _handle_sigterm(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _handle_sigterm)

    server = HTTPServer(("127.0.0.1", port), ProxyHandler)
    print(f"[context_guard] proxy listening on http://127.0.0.1:{port}")
    print(f"[context_guard] rules: {n_rules} active, {n_disabled} disabled, allowlist: {n_allow} entries")
    print(f"[context_guard] set ANTHROPIC_BASE_URL=http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\n[context_guard] shutting down.")
        server.server_close()
    finally:
        _delete_pid()
