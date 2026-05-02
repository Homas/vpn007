# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Tests for vpn007.__main__ — CLI entry point."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from vpn007.__main__ import (
    EXIT_CONFIG_ERROR,
    EXIT_OK,
    main,
    setup_logging,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env_content(domain: str = "vpn.example.com", **overrides: str) -> str:
    """Build a minimal .env file content string."""
    lines = [f"DOMAIN={domain}"]
    for key, val in overrides.items():
        lines.append(f"{key}={val}")
    return "\n".join(lines) + "\n"


def _non_interactive_env() -> dict[str, str]:
    """Return env dict that disables interactive prompts in config loader."""
    return {**os.environ, "AUTO_INSTALL": "y"}


# ---------------------------------------------------------------------------
# Logging setup tests
# ---------------------------------------------------------------------------


class TestSetupLogging:
    """Verify setup_logging configures handlers correctly."""

    def test_creates_log_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "logs" / "deploy.log"
        setup_logging(log_file, debug=False)

        lgr = logging.getLogger("vpn007")
        lgr.info("test message")

        # File should exist after logging
        assert log_file.exists()

        lgr.handlers.clear()

    def test_console_handler_info_level_by_default(self, tmp_path: Path) -> None:
        log_file = tmp_path / "deploy.log"
        setup_logging(log_file, debug=False)

        lgr = logging.getLogger("vpn007")
        stream_handlers = [
            h for h in lgr.handlers if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert len(stream_handlers) == 1
        assert stream_handlers[0].level == logging.INFO

        lgr.handlers.clear()

    def test_console_handler_debug_level_when_debug(self, tmp_path: Path) -> None:
        log_file = tmp_path / "deploy.log"
        setup_logging(log_file, debug=True)

        lgr = logging.getLogger("vpn007")
        stream_handlers = [
            h for h in lgr.handlers if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert len(stream_handlers) == 1
        assert stream_handlers[0].level == logging.DEBUG

        lgr.handlers.clear()

    def test_file_handler_always_debug(self, tmp_path: Path) -> None:
        log_file = tmp_path / "deploy.log"
        setup_logging(log_file, debug=False)

        lgr = logging.getLogger("vpn007")
        file_handlers = [
            h for h in lgr.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 1
        assert file_handlers[0].level == logging.DEBUG

        lgr.handlers.clear()

    def test_no_duplicate_handlers_on_repeated_calls(self, tmp_path: Path) -> None:
        log_file = tmp_path / "deploy.log"
        setup_logging(log_file, debug=False)
        setup_logging(log_file, debug=True)

        lgr = logging.getLogger("vpn007")
        # Should have exactly 2 handlers (1 file + 1 stream), not 4
        assert len(lgr.handlers) == 2

        lgr.handlers.clear()


# ---------------------------------------------------------------------------
# Dry-run execution
# ---------------------------------------------------------------------------


class TestDryRun:
    """Verify successful dry-run execution."""

    @patch("vpn007.config.detect_public_ips", return_value=("203.0.113.1", None))
    @patch.dict(os.environ, {"AUTO_INSTALL": "y"})
    def test_dry_run_exits_zero(
        self, _mock_ips: object, tmp_path: Path
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(_env_content())
        log_file = tmp_path / "deploy.log"

        code = main([
            "--domain", "vpn.example.com",
            "--env-file", str(env_file),
            "--deployment-log-path", str(log_file),
            "--dry-run",
            "--public-ipv4", "203.0.113.1",
        ])
        assert code == EXIT_OK

    @patch("vpn007.config.detect_public_ips", return_value=("203.0.113.1", None))
    @patch.dict(os.environ, {"AUTO_INSTALL": "y"})
    def test_dry_run_logs_steps(
        self, _mock_ips: object, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(_env_content())
        log_file = tmp_path / "deploy.log"

        main([
            "--domain", "vpn.example.com",
            "--env-file", str(env_file),
            "--deployment-log-path", str(log_file),
            "--dry-run",
            "--public-ipv4", "203.0.113.1",
        ])

        captured = capsys.readouterr()
        assert "Dry-run mode" in captured.out
        assert "Dry-run complete" in captured.out


# ---------------------------------------------------------------------------
# Config validation error handling
# ---------------------------------------------------------------------------


class TestConfigValidationErrors:
    """Verify config validation errors produce exit code 1."""

    @patch("vpn007.config.detect_public_ips", return_value=("203.0.113.1", None))
    @patch.dict(os.environ, {"AUTO_INSTALL": "y"})
    def test_missing_domain_exits_with_config_error(
        self, _mock_ips: object, tmp_path: Path
    ) -> None:
        """When no domain is provided, validation should fail with exit code 1."""
        env_file = tmp_path / ".env"
        # Empty .env — no domain
        env_file.write_text("")
        log_file = tmp_path / "deploy.log"

        code = main([
            "--env-file", str(env_file),
            "--deployment-log-path", str(log_file),
            "--public-ipv4", "203.0.113.1",
        ])
        assert code == EXIT_CONFIG_ERROR

    @patch("vpn007.config.detect_public_ips", return_value=("203.0.113.1", None))
    @patch.dict(os.environ, {"AUTO_INSTALL": "y"})
    def test_invalid_domain_exits_with_config_error(
        self, _mock_ips: object, tmp_path: Path
    ) -> None:
        """An invalid domain format should produce exit code 1."""
        env_file = tmp_path / ".env"
        env_file.write_text(_env_content(domain="not-a-valid-domain"))
        log_file = tmp_path / "deploy.log"

        code = main([
            "--env-file", str(env_file),
            "--deployment-log-path", str(log_file),
            "--public-ipv4", "203.0.113.1",
        ])
        assert code == EXIT_CONFIG_ERROR

    @patch("vpn007.config.detect_public_ips", return_value=("203.0.113.1", None))
    @patch.dict(os.environ, {"AUTO_INSTALL": "y"})
    def test_validation_error_logged(
        self, _mock_ips: object, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Validation errors should appear in console output."""
        env_file = tmp_path / ".env"
        # Provide a domain that passes config loading but fails validation
        env_file.write_text(_env_content(domain="invalid"))
        log_file = tmp_path / "deploy.log"

        main([
            "--env-file", str(env_file),
            "--deployment-log-path", str(log_file),
            "--public-ipv4", "203.0.113.1",
        ])

        captured = capsys.readouterr()
        assert "Validation error" in captured.out


# ---------------------------------------------------------------------------
# Missing domain parameter
# ---------------------------------------------------------------------------


class TestMissingDomain:
    """Verify missing domain parameter is reported."""

    @patch("vpn007.config.detect_public_ips", return_value=("203.0.113.1", None))
    @patch.dict(os.environ, {"AUTO_INSTALL": "y"})
    def test_missing_domain_reports_parameter_name(
        self, _mock_ips: object, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("")
        log_file = tmp_path / "deploy.log"

        code = main([
            "--env-file", str(env_file),
            "--deployment-log-path", str(log_file),
            "--public-ipv4", "203.0.113.1",
        ])

        assert code == EXIT_CONFIG_ERROR
        captured = capsys.readouterr()
        # The validator should mention "domain" in the error
        assert "domain" in captured.out.lower()
