# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Tests for vpn007.system_ops module."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from vpn007.models import DeployConfig, DeployError
from vpn007.system_ops import (
    apply_awg_userspace_fallback,
    apply_nftables,
    install_systemd_timers,
    persist_nftables,
    provision_awg_kernel_module,
    smoke_test,
    validate_nginx_config,
    verify_firewall_rules,
)


# ---------------------------------------------------------------------------
# Tests: apply_nftables
# ---------------------------------------------------------------------------


class TestApplyNftables:
    """Tests for apply_nftables."""

    @patch("vpn007.system_ops.subprocess.run")
    def test_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )
        apply_nftables(Path("/tmp/nftables.conf"))
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["nft", "-f", "/tmp/nftables.conf"]

    @patch("vpn007.system_ops.subprocess.run")
    def test_failure_raises_deploy_error(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "nft", output="", stderr="syntax error"
        )
        with pytest.raises(DeployError) as exc_info:
            apply_nftables(Path("/tmp/nftables.conf"))
        assert exc_info.value.service == "firewall"
        assert exc_info.value.step == "apply_nftables"
        assert "syntax error" in exc_info.value.message

    @patch("vpn007.system_ops.subprocess.run")
    def test_nft_not_found_raises_deploy_error(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError("nft not found")
        with pytest.raises(DeployError) as exc_info:
            apply_nftables(Path("/tmp/nftables.conf"))
        assert "not found" in exc_info.value.message


# ---------------------------------------------------------------------------
# Tests: persist_nftables
# ---------------------------------------------------------------------------


class TestPersistNftables:
    """Tests for persist_nftables."""

    @patch("vpn007.system_ops.shutil.copy2")
    def test_success(self, mock_copy: MagicMock) -> None:
        persist_nftables(Path("/tmp/nftables.conf"))
        mock_copy.assert_called_once_with(
            "/tmp/nftables.conf", "/etc/nftables.conf"
        )

    @patch("vpn007.system_ops.shutil.copy2")
    def test_failure_raises_deploy_error(self, mock_copy: MagicMock) -> None:
        mock_copy.side_effect = OSError("Permission denied")
        with pytest.raises(DeployError) as exc_info:
            persist_nftables(Path("/tmp/nftables.conf"))
        assert exc_info.value.service == "firewall"
        assert exc_info.value.step == "persist_nftables"
        assert "Permission denied" in exc_info.value.message


# ---------------------------------------------------------------------------
# Tests: install_systemd_timers
# ---------------------------------------------------------------------------


class TestInstallSystemdTimers:
    """Tests for install_systemd_timers."""

    @patch("vpn007.system_ops.subprocess.run")
    @patch("vpn007.system_ops.shutil.copy2")
    def test_installs_and_enables_timers(
        self, mock_copy: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        # Create mock unit files
        (tmp_path / "blocklist-updater.service").write_text("[Service]\n")
        (tmp_path / "blocklist-updater.timer").write_text("[Timer]\n")
        (tmp_path / "hostname-resolver.service").write_text("[Service]\n")
        (tmp_path / "hostname-resolver.timer").write_text("[Timer]\n")

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        install_systemd_timers(tmp_path)

        # 4 files copied
        assert mock_copy.call_count == 4

        # daemon-reload + 2 timer enables
        assert mock_run.call_count == 3
        daemon_reload_call = mock_run.call_args_list[0]
        assert daemon_reload_call[0][0] == ["systemctl", "daemon-reload"]

        # Timer enable calls
        timer_calls = mock_run.call_args_list[1:]
        timer_names = [c[0][0][-1] for c in timer_calls]
        assert "blocklist-updater.timer" in timer_names
        assert "hostname-resolver.timer" in timer_names

    @patch("vpn007.system_ops.subprocess.run")
    @patch("vpn007.system_ops.shutil.copy2")
    def test_no_unit_files_logs_warning(
        self, mock_copy: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        install_systemd_timers(tmp_path)
        mock_copy.assert_not_called()
        mock_run.assert_not_called()

    @patch("vpn007.system_ops.subprocess.run")
    @patch("vpn007.system_ops.shutil.copy2")
    def test_copy_failure_raises_deploy_error(
        self, mock_copy: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        (tmp_path / "test.timer").write_text("[Timer]\n")
        (tmp_path / "test.service").write_text("[Service]\n")
        mock_copy.side_effect = OSError("Permission denied")

        with pytest.raises(DeployError) as exc_info:
            install_systemd_timers(tmp_path)
        assert exc_info.value.service == "systemd"

    @patch("vpn007.system_ops.subprocess.run")
    @patch("vpn007.system_ops.shutil.copy2")
    def test_daemon_reload_failure_raises_deploy_error(
        self, mock_copy: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        (tmp_path / "test.timer").write_text("[Timer]\n")
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "systemctl", output="", stderr="failed"
        )

        with pytest.raises(DeployError) as exc_info:
            install_systemd_timers(tmp_path)
        assert "daemon-reload" in exc_info.value.message

    @patch("vpn007.system_ops.subprocess.run")
    @patch("vpn007.system_ops.shutil.copy2")
    def test_systemctl_not_found_raises_deploy_error(
        self, mock_copy: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        (tmp_path / "test.timer").write_text("[Timer]\n")
        mock_run.side_effect = FileNotFoundError("systemctl not found")

        with pytest.raises(DeployError) as exc_info:
            install_systemd_timers(tmp_path)
        assert "systemctl" in exc_info.value.message


# ---------------------------------------------------------------------------
# Tests: provision_awg_kernel_module
# ---------------------------------------------------------------------------


class TestProvisionAwgKernelModule:
    """Tests for provision_awg_kernel_module."""

    def test_alpine_skips_kernel_module(self) -> None:
        result = provision_awg_kernel_module("alpine")
        assert result is False

    def test_unsupported_distro_returns_false(self) -> None:
        result = provision_awg_kernel_module("fedora")
        assert result is False

    @patch("vpn007.system_ops._is_module_loaded", return_value=True)
    def test_module_already_loaded(self, mock_loaded: MagicMock) -> None:
        result = provision_awg_kernel_module("ubuntu")
        assert result is True
        mock_loaded.assert_called_once_with("amneziawg")

    @patch("vpn007.system_ops._persist_module_load")
    @patch("vpn007.system_ops._is_module_loaded", side_effect=[False, True])
    @patch("vpn007.system_ops._install_awg_package", return_value=True)
    @patch("vpn007.system_ops._install_awg_prerequisites", return_value=True)
    def test_full_provisioning_success(
        self,
        mock_prereqs: MagicMock,
        mock_package: MagicMock,
        mock_loaded: MagicMock,
        mock_persist: MagicMock,
    ) -> None:
        result = provision_awg_kernel_module("ubuntu")
        assert result is True
        mock_prereqs.assert_called_once_with("ubuntu")
        mock_package.assert_called_once_with("ubuntu")
        mock_persist.assert_called_once_with("amneziawg")

    @patch("vpn007.system_ops._install_awg_prerequisites", return_value=False)
    @patch("vpn007.system_ops._is_module_loaded", return_value=False)
    def test_prerequisite_failure_returns_false(
        self, mock_loaded: MagicMock, mock_prereqs: MagicMock
    ) -> None:
        result = provision_awg_kernel_module("ubuntu")
        assert result is False

    @patch("vpn007.system_ops._install_awg_package", return_value=False)
    @patch("vpn007.system_ops._install_awg_prerequisites", return_value=True)
    @patch("vpn007.system_ops._is_module_loaded", return_value=False)
    def test_package_install_failure_returns_false(
        self,
        mock_loaded: MagicMock,
        mock_prereqs: MagicMock,
        mock_package: MagicMock,
    ) -> None:
        result = provision_awg_kernel_module("ubuntu")
        assert result is False


# ---------------------------------------------------------------------------
# Tests: _is_module_loaded
# ---------------------------------------------------------------------------


class TestIsModuleLoaded:
    """Tests for _is_module_loaded helper."""

    @patch("vpn007.system_ops.subprocess.run")
    def test_module_found(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _is_module_loaded

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Module                  Size  Used by\namneziawg              65536  0\n",
        )
        assert _is_module_loaded("amneziawg") is True

    @patch("vpn007.system_ops.subprocess.run")
    def test_module_not_found(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _is_module_loaded

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Module                  Size  Used by\nwireguard              65536  0\n",
        )
        assert _is_module_loaded("amneziawg") is False

    @patch("vpn007.system_ops.subprocess.run")
    def test_lsmod_failure(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _is_module_loaded

        mock_run.side_effect = FileNotFoundError("lsmod not found")
        assert _is_module_loaded("amneziawg") is False


# ---------------------------------------------------------------------------
# Tests: apply_awg_userspace_fallback
# ---------------------------------------------------------------------------


class TestApplyAwgUserspaceFallback:
    """Tests for apply_awg_userspace_fallback."""

    @patch("vpn007.system_ops.subprocess.run")
    def test_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        apply_awg_userspace_fallback(
            Path("/tmp/docker-compose.yml"), "vpn007"
        )
        assert mock_run.call_count == 2

        # First call: build
        build_cmd = mock_run.call_args_list[0][0][0]
        assert "build" in build_cmd
        assert "amneziawg" in build_cmd

        # Second call: up
        up_cmd = mock_run.call_args_list[1][0][0]
        assert "up" in up_cmd
        assert "-d" in up_cmd
        assert "amneziawg" in up_cmd

    @patch("vpn007.system_ops.subprocess.run")
    def test_build_failure_raises_deploy_error(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "docker compose build", output="", stderr="build failed"
        )
        with pytest.raises(DeployError) as exc_info:
            apply_awg_userspace_fallback(
                Path("/tmp/docker-compose.yml"), "vpn007"
            )
        assert exc_info.value.service == "amneziawg"
        assert "build" in exc_info.value.message

    @patch("vpn007.system_ops.subprocess.run")
    def test_up_failure_raises_deploy_error(self, mock_run: MagicMock) -> None:
        # Build succeeds, up fails
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            subprocess.CalledProcessError(
                1, "docker compose up", output="", stderr="up failed"
            ),
        ]
        with pytest.raises(DeployError) as exc_info:
            apply_awg_userspace_fallback(
                Path("/tmp/docker-compose.yml"), "vpn007"
            )
        assert exc_info.value.service == "amneziawg"


# ---------------------------------------------------------------------------
# Tests: verify_firewall_rules
# ---------------------------------------------------------------------------


class TestVerifyFirewallRules:
    """Tests for verify_firewall_rules."""

    @patch("vpn007.system_ops.subprocess.run")
    def test_rules_active(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "table inet filter {\n"
                "  chain input {\n"
                "    type filter hook input priority 0; policy drop;\n"
                "  }\n"
                "  chain output {\n"
                "    type filter hook output priority 0; policy accept;\n"
                "  }\n"
                "}\n"
            ),
            stderr="",
        )
        assert verify_firewall_rules() is True

    @patch("vpn007.system_ops.subprocess.run")
    def test_no_filter_table(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="table ip nat {\n}\n", stderr=""
        )
        assert verify_firewall_rules() is False

    @patch("vpn007.system_ops.subprocess.run")
    def test_nft_command_fails(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="error"
        )
        assert verify_firewall_rules() is False

    @patch("vpn007.system_ops.subprocess.run")
    def test_nft_not_found(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError("nft not found")
        assert verify_firewall_rules() is False

    @patch("vpn007.system_ops.subprocess.run")
    def test_missing_policy_drop(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "table inet filter {\n"
                "  chain input {\n"
                "    type filter hook input priority 0; policy accept;\n"
                "  }\n"
                "  chain output {\n"
                "    type filter hook output priority 0;\n"
                "  }\n"
                "}\n"
            ),
            stderr="",
        )
        assert verify_firewall_rules() is False


# ---------------------------------------------------------------------------
# Tests: validate_nginx_config
# ---------------------------------------------------------------------------


class TestValidateNginxConfig:
    """Tests for validate_nginx_config."""

    @patch("vpn007.system_ops.subprocess.run")
    def test_valid_config(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="nginx: configuration file /etc/nginx/nginx.conf test is successful",
        )
        assert validate_nginx_config(Path("/tmp/docker-compose.yml")) is True
        cmd = mock_run.call_args[0][0]
        assert "nginx" in cmd
        assert "-t" in cmd
        assert "reverse_proxy" in cmd

    @patch("vpn007.system_ops.subprocess.run")
    def test_invalid_config(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="nginx: [emerg] unknown directive",
        )
        assert validate_nginx_config(Path("/tmp/docker-compose.yml")) is False

    @patch("vpn007.system_ops.subprocess.run")
    def test_docker_not_found(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError("docker not found")
        assert validate_nginx_config(Path("/tmp/docker-compose.yml")) is False


# ---------------------------------------------------------------------------
# Tests: smoke_test
# ---------------------------------------------------------------------------


class TestSmokeTest:
    """Tests for smoke_test."""

    @patch("vpn007.system_ops._check_container_health", return_value=True)
    @patch("vpn007.system_ops._check_cover_site", return_value=True)
    def test_all_pass(
        self, mock_cover: MagicMock, mock_health: MagicMock
    ) -> None:
        config = DeployConfig(domain="vpn.example.com")
        results = smoke_test(config)
        assert results["cover_site_responds"] is True
        assert results["containers_healthy"] is True

    @patch("vpn007.system_ops._check_container_health", return_value=False)
    @patch("vpn007.system_ops._check_cover_site", return_value=False)
    def test_all_fail(
        self, mock_cover: MagicMock, mock_health: MagicMock
    ) -> None:
        config = DeployConfig(domain="vpn.example.com")
        results = smoke_test(config)
        assert results["cover_site_responds"] is False
        assert results["containers_healthy"] is False

    @patch("vpn007.system_ops._check_container_health", return_value=True)
    @patch("vpn007.system_ops._check_cover_site", return_value=False)
    def test_partial_failure(
        self, mock_cover: MagicMock, mock_health: MagicMock
    ) -> None:
        config = DeployConfig(domain="vpn.example.com")
        results = smoke_test(config)
        assert results["cover_site_responds"] is False
        assert results["containers_healthy"] is True


# ---------------------------------------------------------------------------
# Tests: _check_cover_site
# ---------------------------------------------------------------------------


class TestCheckCoverSite:
    """Tests for _check_cover_site helper."""

    @patch("vpn007.system_ops.subprocess.run")
    def test_success_200(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _check_cover_site

        mock_run.return_value = MagicMock(
            returncode=0, stdout="200", stderr=""
        )
        assert _check_cover_site("vpn.example.com") is True
        cmd = mock_run.call_args[0][0]
        assert "curl" in cmd
        assert "--insecure" in cmd
        assert "https://vpn.example.com/" in cmd

    @patch("vpn007.system_ops.subprocess.run")
    def test_success_301(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _check_cover_site

        mock_run.return_value = MagicMock(
            returncode=0, stdout="301", stderr=""
        )
        assert _check_cover_site("vpn.example.com") is True

    @patch("vpn007.system_ops.subprocess.run")
    def test_failure_500(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _check_cover_site

        mock_run.return_value = MagicMock(
            returncode=0, stdout="500", stderr=""
        )
        assert _check_cover_site("vpn.example.com") is False

    @patch("vpn007.system_ops.subprocess.run")
    def test_curl_timeout(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _check_cover_site

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="curl", timeout=15
        )
        assert _check_cover_site("vpn.example.com") is False


# ---------------------------------------------------------------------------
# Tests: _check_container_health
# ---------------------------------------------------------------------------


class TestCheckContainerHealth:
    """Tests for _check_container_health helper."""

    @patch("vpn007.system_ops.subprocess.run")
    def test_all_running(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _check_container_health

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
        assert _check_container_health(Path("/tmp/docker-compose.yml")) is True

    @patch("vpn007.system_ops.subprocess.run")
    def test_missing_service(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _check_container_health

        ps_output = json.dumps([
            {"Service": "reverse_proxy", "State": "running"},
            {"Service": "three_x_ui", "State": "running"},
        ])
        mock_run.return_value = MagicMock(
            returncode=0, stdout=ps_output, stderr=""
        )
        assert _check_container_health(Path("/tmp/docker-compose.yml")) is False

    @patch("vpn007.system_ops.subprocess.run")
    def test_service_not_running(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _check_container_health

        ps_output = json.dumps([
            {"Service": "reverse_proxy", "State": "running"},
            {"Service": "three_x_ui", "State": "exited"},
            {"Service": "amneziawg", "State": "running"},
            {"Service": "tailscale", "State": "running"},
            {"Service": "cover_site", "State": "running"},
        ])
        mock_run.return_value = MagicMock(
            returncode=0, stdout=ps_output, stderr=""
        )
        assert _check_container_health(Path("/tmp/docker-compose.yml")) is False

    @patch("vpn007.system_ops.subprocess.run")
    def test_empty_output(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _check_container_health

        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )
        assert _check_container_health(Path("/tmp/docker-compose.yml")) is False

    @patch("vpn007.system_ops.subprocess.run")
    def test_command_failure(self, mock_run: MagicMock) -> None:
        from vpn007.system_ops import _check_container_health

        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="error"
        )
        assert _check_container_health(Path("/tmp/docker-compose.yml")) is False
