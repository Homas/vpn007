# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Tests for vpn007.docker_ops module."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from vpn007.docker_ops import (
    MAX_RETRIES,
    RETRY_DELAY_SECONDS,
    check_existing_deployment,
    compose_pull,
    compose_up,
)


# ---------------------------------------------------------------------------
# Tests: compose_up
# ---------------------------------------------------------------------------


class TestComposeUp:
    """Tests for compose_up with retry logic."""

    @patch("vpn007.docker_ops.subprocess.run")
    def test_success_on_first_attempt(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="done", stderr=""
        )
        compose_up(Path("/tmp/docker-compose.yml"), "vpn007")
        assert mock_run.call_count == 1
        cmd = mock_run.call_args_list[0][0][0]
        assert "docker" in cmd
        assert "compose" in cmd
        assert "up" in cmd
        assert "-d" in cmd
        assert "-f" in cmd
        assert "/tmp/docker-compose.yml" in cmd
        assert "--project-name" in cmd
        assert "vpn007" in cmd

    @patch("vpn007.docker_ops.time.sleep")
    @patch("vpn007.docker_ops.subprocess.run")
    def test_success_on_second_attempt(
        self, mock_run: MagicMock, mock_sleep: MagicMock
    ) -> None:
        # First call: compose up fails; second call: logs; third call: compose up succeeds
        mock_run.side_effect = [
            subprocess.CalledProcessError(
                1, "docker compose up", output="", stderr="error starting"
            ),
            MagicMock(returncode=0, stdout="container logs", stderr=""),  # logs
            MagicMock(returncode=0, stdout="done", stderr=""),  # retry success
        ]
        compose_up(Path("/tmp/docker-compose.yml"), "vpn007")
        mock_sleep.assert_called_once_with(RETRY_DELAY_SECONDS)

    @patch("vpn007.docker_ops.time.sleep")
    @patch("vpn007.docker_ops.subprocess.run")
    def test_all_attempts_exhausted_raises(
        self, mock_run: MagicMock, mock_sleep: MagicMock
    ) -> None:
        # Each compose up fails, each logs call succeeds
        effects = []
        for _ in range(MAX_RETRIES):
            effects.append(
                subprocess.CalledProcessError(
                    1, "docker compose up", output="", stderr="fail"
                )
            )
            effects.append(
                MagicMock(returncode=0, stdout="logs", stderr="")
            )
        mock_run.side_effect = effects

        with pytest.raises(subprocess.CalledProcessError):
            compose_up(Path("/tmp/docker-compose.yml"), "vpn007")

        # Should have slept between attempts (MAX_RETRIES - 1 times)
        assert mock_sleep.call_count == MAX_RETRIES - 1

    @patch("vpn007.docker_ops.time.sleep")
    @patch("vpn007.docker_ops.subprocess.run")
    def test_retry_delay_is_5_seconds(
        self, mock_run: MagicMock, mock_sleep: MagicMock
    ) -> None:
        effects = []
        for _ in range(MAX_RETRIES):
            effects.append(
                subprocess.CalledProcessError(
                    1, "docker compose up", output="", stderr="fail"
                )
            )
            effects.append(
                MagicMock(returncode=0, stdout="", stderr="")
            )
        mock_run.side_effect = effects

        with pytest.raises(subprocess.CalledProcessError):
            compose_up(Path("/tmp/docker-compose.yml"), "test")

        for c in mock_sleep.call_args_list:
            assert c == call(5)

    @patch("vpn007.docker_ops.time.sleep")
    @patch("vpn007.docker_ops.subprocess.run")
    def test_max_retries_is_3(
        self, mock_run: MagicMock, mock_sleep: MagicMock
    ) -> None:
        assert MAX_RETRIES == 3

    @patch("vpn007.docker_ops.subprocess.run")
    def test_logs_captured_on_failure(self, mock_run: MagicMock) -> None:
        """Verify that container logs are fetched after a failed attempt."""
        effects = []
        for _ in range(MAX_RETRIES):
            effects.append(
                subprocess.CalledProcessError(
                    1, "docker compose up", output="", stderr="fail"
                )
            )
            effects.append(
                MagicMock(returncode=0, stdout="container log output", stderr="")
            )
        mock_run.side_effect = effects

        with pytest.raises(subprocess.CalledProcessError):
            compose_up(Path("/tmp/compose.yml"), "proj")

        # Check that logs command was called after each failure
        log_calls = [
            c
            for c in mock_run.call_args_list
            if "logs" in c[0][0]
        ]
        assert len(log_calls) == MAX_RETRIES


# ---------------------------------------------------------------------------
# Tests: compose_pull
# ---------------------------------------------------------------------------


class TestComposePull:
    """Tests for compose_pull."""

    @patch("vpn007.docker_ops.subprocess.run")
    def test_pull_all_services(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        compose_pull(Path("/tmp/docker-compose.yml"))
        cmd = mock_run.call_args[0][0]
        assert "pull" in cmd
        assert "-f" in cmd
        assert "/tmp/docker-compose.yml" in cmd
        # No service name appended
        assert cmd[-1] == "pull"

    @patch("vpn007.docker_ops.subprocess.run")
    def test_pull_specific_service(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        compose_pull(Path("/tmp/docker-compose.yml"), service="reverse_proxy")
        cmd = mock_run.call_args[0][0]
        assert "pull" in cmd
        assert cmd[-1] == "reverse_proxy"

    @patch("vpn007.docker_ops.subprocess.run")
    def test_pull_failure_raises(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "docker compose pull", output="", stderr="pull failed"
        )
        with pytest.raises(subprocess.CalledProcessError):
            compose_pull(Path("/tmp/docker-compose.yml"))

    @patch("vpn007.docker_ops.subprocess.run")
    def test_pull_uses_compose_file_path(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        path = Path("/opt/deploy/docker-compose.yml")
        compose_pull(path, service="three_x_ui")
        cmd = mock_run.call_args[0][0]
        assert str(path) in cmd


# ---------------------------------------------------------------------------
# Tests: check_existing_deployment
# ---------------------------------------------------------------------------


class TestCheckExistingDeployment:
    """Tests for check_existing_deployment."""

    @patch("vpn007.docker_ops.subprocess.run")
    def test_running_services_detected(self, mock_run: MagicMock) -> None:
        ps_output = json.dumps([
            {"Service": "reverse_proxy", "State": "running"},
            {"Service": "three_x_ui", "State": "running"},
            {"Service": "amneziawg", "State": "exited"},
        ])
        mock_run.return_value = MagicMock(
            returncode=0, stdout=ps_output, stderr=""
        )
        result = check_existing_deployment(Path("/tmp/docker-compose.yml"))
        assert result["reverse_proxy"] is True
        assert result["three_x_ui"] is True
        assert result["amneziawg"] is False

    @patch("vpn007.docker_ops.subprocess.run")
    def test_no_existing_deployment(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )
        result = check_existing_deployment(Path("/tmp/docker-compose.yml"))
        assert result == {}

    @patch("vpn007.docker_ops.subprocess.run")
    def test_command_failure_returns_empty(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="error"
        )
        result = check_existing_deployment(Path("/tmp/docker-compose.yml"))
        assert result == {}

    @patch("vpn007.docker_ops.subprocess.run")
    def test_timeout_returns_empty(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="docker compose ps", timeout=30
        )
        result = check_existing_deployment(Path("/tmp/docker-compose.yml"))
        assert result == {}

    @patch("vpn007.docker_ops.subprocess.run")
    def test_file_not_found_returns_empty(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError("docker not found")
        result = check_existing_deployment(Path("/tmp/docker-compose.yml"))
        assert result == {}

    @patch("vpn007.docker_ops.subprocess.run")
    def test_line_by_line_json_parsing(self, mock_run: MagicMock) -> None:
        """Older Docker Compose versions output one JSON object per line."""
        lines = "\n".join([
            json.dumps({"Service": "reverse_proxy", "State": "running"}),
            json.dumps({"Service": "cover_site", "State": "running"}),
        ])
        mock_run.return_value = MagicMock(
            returncode=0, stdout=lines, stderr=""
        )
        result = check_existing_deployment(Path("/tmp/docker-compose.yml"))
        assert result["reverse_proxy"] is True
        assert result["cover_site"] is True

    @patch("vpn007.docker_ops.subprocess.run")
    def test_name_field_fallback(self, mock_run: MagicMock) -> None:
        """Some compose versions use 'Name' instead of 'Service'."""
        ps_output = json.dumps([
            {"Name": "vpn007-reverse_proxy-1", "State": "running"},
        ])
        mock_run.return_value = MagicMock(
            returncode=0, stdout=ps_output, stderr=""
        )
        result = check_existing_deployment(Path("/tmp/docker-compose.yml"))
        assert result["vpn007-reverse_proxy-1"] is True

    @patch("vpn007.docker_ops.subprocess.run")
    def test_all_services_running(self, mock_run: MagicMock) -> None:
        ps_output = json.dumps([
            {"Service": "reverse_proxy", "State": "running"},
            {"Service": "three_x_ui", "State": "running"},
            {"Service": "amneziawg", "State": "running"},
            {"Service": "tailscale", "State": "running"},
            {"Service": "cover_site", "State": "running"},
        ])
        mock_run.return_value = MagicMock(
            returncode=0, stdout=ps_output, stderr=""
        )
        result = check_existing_deployment(Path("/tmp/docker-compose.yml"))
        assert len(result) == 5
        assert all(v is True for v in result.values())

    @patch("vpn007.docker_ops.subprocess.run")
    def test_invalid_json_returns_empty(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="not valid json at all", stderr=""
        )
        result = check_existing_deployment(Path("/tmp/docker-compose.yml"))
        assert result == {}

    @patch("vpn007.docker_ops.subprocess.run")
    def test_compose_path_passed_correctly(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )
        path = Path("/opt/deploy/docker-compose.yml")
        check_existing_deployment(path)
        cmd = mock_run.call_args[0][0]
        assert str(path) in cmd
        assert "--format" in cmd
        assert "json" in cmd
