"""
Tests for proxy server: pause/resume config toggle, _is_enabled, and PID management.
HTTP forwarding tests are marked for manual verification (require upstream mock).
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from proxy.server import _is_enabled


class TestIsEnabled:
    def test_default_true_no_config(self, tmp_path):
        """No config file → enabled by default."""
        fake = tmp_path / "nope.json"
        with patch("proxy.server.CONFIG_PATH", fake), \
             patch("proxy.server._LOCAL_CONFIG", fake):
            assert _is_enabled() is True

    def test_enabled_true(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"enabled": True}))
        with patch("proxy.server.CONFIG_PATH", cfg):
            assert _is_enabled() is True

    def test_enabled_false(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"enabled": False}))
        with patch("proxy.server.CONFIG_PATH", cfg):
            assert _is_enabled() is False

    def test_malformed_json_returns_true(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text("not json {{{")
        with patch("proxy.server.CONFIG_PATH", cfg):
            assert _is_enabled() is True

    def test_missing_enabled_key_returns_true(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"port": 9000}))
        with patch("proxy.server.CONFIG_PATH", cfg):
            assert _is_enabled() is True


class TestPauseResumeConfig:
    """Test that pause/resume modifies the config file correctly."""

    def test_pause_sets_false(self, tmp_path, monkeypatch):
        import importlib.util
        import importlib.machinery
        import sys as _sys

        repo_root = Path(__file__).parent.parent
        if str(repo_root) not in _sys.path:
            _sys.path.insert(0, str(repo_root))

        cg_path = repo_root / "cg"
        loader = importlib.machinery.SourceFileLoader("cg_module", str(cg_path))
        spec = importlib.util.spec_from_loader("cg_module", loader, origin=str(cg_path))
        cg_mod = importlib.util.module_from_spec(spec)
        cg_mod.__file__ = str(cg_path)
        spec.loader.exec_module(cg_mod)

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"enabled": True, "port": 8765}))
        monkeypatch.setattr(cg_mod, "_CONFIG_FILE", config_file)
        monkeypatch.setattr(cg_mod, "_LOCAL_CONFIG", config_file)

        # Simulate "running" proxy
        pid_file = tmp_path / "proxy.pid"
        import os
        pid_file.write_text(str(os.getpid()))  # current process is "alive"
        monkeypatch.setattr(cg_mod, "_PID_FILE", pid_file)

        cg_mod.cmd_pause()
        data = json.loads(config_file.read_text())
        assert data["enabled"] is False

    def test_resume_sets_true(self, tmp_path, monkeypatch):
        import importlib.util
        import importlib.machinery
        import sys as _sys

        repo_root = Path(__file__).parent.parent
        if str(repo_root) not in _sys.path:
            _sys.path.insert(0, str(repo_root))

        cg_path = repo_root / "cg"
        loader = importlib.machinery.SourceFileLoader("cg_module", str(cg_path))
        spec = importlib.util.spec_from_loader("cg_module", loader, origin=str(cg_path))
        cg_mod = importlib.util.module_from_spec(spec)
        cg_mod.__file__ = str(cg_path)
        spec.loader.exec_module(cg_mod)

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"enabled": False, "port": 8765}))
        monkeypatch.setattr(cg_mod, "_CONFIG_FILE", config_file)
        monkeypatch.setattr(cg_mod, "_LOCAL_CONFIG", config_file)

        pid_file = tmp_path / "proxy.pid"
        import os
        pid_file.write_text(str(os.getpid()))
        monkeypatch.setattr(cg_mod, "_PID_FILE", pid_file)

        cg_mod.cmd_resume()
        data = json.loads(config_file.read_text())
        assert data["enabled"] is True
