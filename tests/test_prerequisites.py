# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Tests for vpn007.prerequisites module."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vpn007.prerequisites import (
    _extract_version,
    _parse_version,
    check_dependencies,
    check_docker_daemon,
    check_kernel_capabilities,
    check_system_resources,
    detect_os,
    get_missing_dependencies,
    install_missing_dependencies,
    run_prerequisite_checks,
    validate_os,
)


# ---------------------------------------------------------------------------
# Helper: mock /etc/os-release content
# ---------------------------------------------------------------------------

UBUNTU_2204 = 'ID=ubuntu\nVERSION_ID="22.04"\nNAME="Ubuntu"\n'
DEBIAN_12 = 'ID=debian\nVERSION_ID="12"\nNAME="Debian GNU/Linux"\n'
ALPINE_318 = 'ID=alpine\nVERSION_ID="3.18.4"\nNAME="Alpine Linux"\n'
DEBIAN_10 = 'ID=debian\nVERSION_ID="10"\nNAME="Debian GNU/Linux"\n'
UBUNTU_2004 = 'ID=ubuntu\nVERSION_ID="20.04"\nNAME="Ubuntu"\n'
ALPINE_317 = 'ID=alpine\nVERSION_ID="3.17.0"\nNAME="Alpine Linux"\n'
FEDORA_39 = 'ID=fedora\nVERSION_ID="39"\nNAME="Fedora Linux"\n'
MISSING_ID = 'VERSION_ID="22.04"\nNAME="Ubuntu"\n'
MISSING_VERSION = 'ID=ubuntu\nNAME="Ubuntu"\n'


# ---------------------------------------------------------------------------
# Tests: _parse_version
# ---------------------------------------------------------------------------


class TestParseVersion:
    def test_simple_major(self) -> None:
        assert _parse_version("12") == (12,)

    def test_major_minor(self) -> None:
        assert _parse_version("22.04") == (22, 4)

    def test_major_minor_patch(self) -> None:
        assert _parse_version("3.18.4") == (3, 18, 4)

    def test_alpine_suffix(self) -> None:
        assert _parse_version("3.18.4-r0") == (3, 18, 4)

    def test_long_version(self) -> None:
        assert _parse_version("20.10.17") == (20, 10, 17)


# ---------------------------------------------------------------------------
# Tests: _extract_version
# ---------------------------------------------------------------------------


class TestExtractVersion:
    def test_docker_version_output(self) -> None:
        output = "Docker version 24.0.7, build afdd53b"
        assert _extract_version(output) == "24.0.7"

    def test_python_version_output(self) -> None:
        output = "Python 3.14.0"
        assert _extract_version(output) == "3.14.0"

    def test_nft_version_output(self) -> None:
        output = "nftables v1.0.6 (Lester Gooch #3)"
        assert _extract_version(output) == "1.0.6"

    def test_curl_version_output(self) -> None:
        output = "curl 8.4.0 (x86_64-pc-linux-gnu)"
        assert _extract_version(output) == "8.4.0"

    def test_git_version_output(self) -> None:
        output = "git version 2.43.0"
        assert _extract_version(output) == "2.43.0"

    def test_compose_version_output(self) -> None:
        output = "Docker Compose version v2.24.5"
        assert _extract_version(output) == "2.24.5"

    def test_no_version_found(self) -> None:
        assert _extract_version("no version here") is None


# ---------------------------------------------------------------------------
# Tests: detect_os
# ---------------------------------------------------------------------------


class TestDetectOS:
    @patch("vpn007.prerequisites.Path.read_text", return_value=UBUNTU_2204)
    def test_detect_ubuntu(self, mock_read: MagicMock) -> None:
        distro, version = detect_os()
        assert distro == "ubuntu"
        assert version == "22.04"

    @patch("vpn007.prerequisites.Path.read_text", return_value=DEBIAN_12)
    def test_detect_debian(self, mock_read: MagicMock) -> None:
        distro, version = detect_os()
        assert distro == "debian"
        assert version == "12"

    @patch("vpn007.prerequisites.Path.read_text", return_value=ALPINE_318)
    def test_detect_alpine(self, mock_read: MagicMock) -> None:
        distro, version = detect_os()
        assert distro == "alpine"
        assert version == "3.18.4"

    @patch("vpn007.prerequisites.Path.read_text", side_effect=FileNotFoundError)
    def test_missing_os_release(self, mock_read: MagicMock) -> None:
        with pytest.raises(FileNotFoundError):
            detect_os()

    @patch("vpn007.prerequisites.Path.read_text", return_value=MISSING_ID)
    def test_missing_id_field(self, mock_read: MagicMock) -> None:
        with pytest.raises(ValueError, match="distribution ID"):
            detect_os()

    @patch("vpn007.prerequisites.Path.read_text", return_value=MISSING_VERSION)
    def test_missing_version_field(self, mock_read: MagicMock) -> None:
        with pytest.raises(ValueError, match="VERSION_ID"):
            detect_os()


# ---------------------------------------------------------------------------
# Tests: validate_os
# ---------------------------------------------------------------------------


class TestValidateOS:
    def test_ubuntu_2204_supported(self) -> None:
        assert validate_os("ubuntu", "22.04") == []

    def test_ubuntu_2404_supported(self) -> None:
        assert validate_os("ubuntu", "24.04") == []

    def test_ubuntu_2004_too_old(self) -> None:
        errors = validate_os("ubuntu", "20.04")
        assert len(errors) == 1
        assert "below the minimum" in errors[0]

    def test_debian_11_supported(self) -> None:
        assert validate_os("debian", "11") == []

    def test_debian_12_supported(self) -> None:
        assert validate_os("debian", "12") == []

    def test_debian_10_too_old(self) -> None:
        errors = validate_os("debian", "10")
        assert len(errors) == 1
        assert "below the minimum" in errors[0]

    def test_alpine_318_supported(self) -> None:
        assert validate_os("alpine", "3.18.4") == []

    def test_alpine_319_supported(self) -> None:
        assert validate_os("alpine", "3.19.0") == []

    def test_alpine_317_too_old(self) -> None:
        errors = validate_os("alpine", "3.17.0")
        assert len(errors) == 1
        assert "below the minimum" in errors[0]

    def test_fedora_unsupported(self) -> None:
        errors = validate_os("fedora", "39")
        assert len(errors) == 1
        assert "Unsupported OS" in errors[0]
        assert "fedora" in errors[0].lower()

    def test_centos_unsupported(self) -> None:
        errors = validate_os("centos", "9")
        assert len(errors) == 1
        assert "Unsupported OS" in errors[0]

    def test_case_insensitive_distro(self) -> None:
        assert validate_os("Ubuntu", "22.04") == []
        assert validate_os("DEBIAN", "12") == []
        assert validate_os("Alpine", "3.18") == []


# ---------------------------------------------------------------------------
# Tests: check_dependencies
# ---------------------------------------------------------------------------


class TestCheckDependencies:
    @patch("vpn007.prerequisites.shutil.which")
    @patch("vpn007.prerequisites.subprocess.run")
    def test_all_deps_present(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/mock"
        mock_run.return_value = MagicMock(
            stdout="version 99.0.0", stderr="", returncode=0
        )
        deps = check_dependencies()
        assert all(v is not None for v in deps.values())
        assert len(deps) == 6

    @patch("vpn007.prerequisites.shutil.which", return_value=None)
    def test_all_deps_missing(self, mock_which: MagicMock) -> None:
        deps = check_dependencies()
        assert all(v is None for v in deps.values())

    @patch("vpn007.prerequisites.shutil.which")
    @patch("vpn007.prerequisites.subprocess.run")
    def test_docker_version_parsed(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/docker"

        def side_effect(cmd, **kwargs):
            if cmd == ["docker", "--version"]:
                return MagicMock(
                    stdout="Docker version 24.0.7, build afdd53b",
                    stderr="",
                    returncode=0,
                )
            if cmd == ["docker", "compose", "version"]:
                return MagicMock(
                    stdout="Docker Compose version v2.24.5",
                    stderr="",
                    returncode=0,
                )
            return MagicMock(stdout="version 99.0.0", stderr="", returncode=0)

        mock_run.side_effect = side_effect
        deps = check_dependencies()
        assert deps["docker"] == "24.0.7"
        assert deps["docker-compose"] == "2.24.5"

    @patch("vpn007.prerequisites.shutil.which")
    @patch(
        "vpn007.prerequisites.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="test", timeout=10),
    )
    def test_timeout_returns_none(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/mock"
        deps = check_dependencies()
        assert all(v is None for v in deps.values())


# ---------------------------------------------------------------------------
# Tests: get_missing_dependencies
# ---------------------------------------------------------------------------


class TestGetMissingDependencies:
    def test_all_present_and_sufficient(self) -> None:
        deps = {
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": "3.14.0",
            "nftables": "1.0.6",
            "curl": "8.4.0",
            "git": "2.43.0",
        }
        assert get_missing_dependencies(deps) == []

    def test_missing_dependency(self) -> None:
        deps = {
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": None,
            "nftables": "1.0.6",
            "curl": "8.4.0",
            "git": "2.43.0",
        }
        missing = get_missing_dependencies(deps)
        assert missing == ["python3"]

    def test_outdated_dependency(self) -> None:
        deps = {
            "docker": "19.0.0",
            "docker-compose": "2.24.5",
            "python3": "3.14.0",
            "nftables": "1.0.6",
            "curl": "8.4.0",
            "git": "2.43.0",
        }
        missing = get_missing_dependencies(deps)
        assert "docker" in missing

    def test_multiple_missing(self) -> None:
        deps = {
            "docker": None,
            "docker-compose": None,
            "python3": "3.14.0",
            "nftables": None,
            "curl": "8.4.0",
            "git": "2.43.0",
        }
        missing = get_missing_dependencies(deps)
        assert set(missing) == {"docker", "docker-compose", "nftables"}

    def test_python_below_minimum(self) -> None:
        deps = {
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": "3.11.0",
            "nftables": "1.0.6",
            "curl": "8.4.0",
            "git": "2.43.0",
        }
        missing = get_missing_dependencies(deps)
        assert "python3" in missing


# ---------------------------------------------------------------------------
# Tests: install_missing_dependencies
# ---------------------------------------------------------------------------


class TestInstallMissingDependencies:
    @patch("vpn007.prerequisites.subprocess.run")
    def test_apt_install_debian(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        cmd = install_missing_dependencies(["curl", "git"], "debian")
        assert cmd[0] == "apt-get"
        assert "curl" in cmd
        assert "git" in cmd

    @patch("vpn007.prerequisites.subprocess.run")
    def test_apt_install_ubuntu(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        cmd = install_missing_dependencies(["docker"], "ubuntu")
        assert cmd[0] == "apt-get"
        assert "docker-ce" in cmd

    @patch("vpn007.prerequisites.subprocess.run")
    def test_apk_install_alpine(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        cmd = install_missing_dependencies(["curl", "git"], "alpine")
        assert cmd[0] == "apk"
        assert "--no-cache" in cmd
        assert "curl" in cmd
        assert "git" in cmd

    def test_empty_missing_list(self) -> None:
        cmd = install_missing_dependencies([], "debian")
        assert cmd == []

    def test_unsupported_distro_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported distro"):
            install_missing_dependencies(["curl"], "fedora")

    @patch("vpn007.prerequisites.subprocess.run")
    def test_docker_compose_package_name_debian(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        cmd = install_missing_dependencies(["docker-compose"], "debian")
        assert "docker-compose-plugin" in cmd

    @patch("vpn007.prerequisites.subprocess.run")
    def test_docker_compose_package_name_alpine(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        cmd = install_missing_dependencies(["docker-compose"], "alpine")
        assert "docker-cli-compose" in cmd

    @patch(
        "vpn007.prerequisites.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "apt-get"),
    )
    def test_install_failure_raises(self, mock_run: MagicMock) -> None:
        with pytest.raises(subprocess.CalledProcessError):
            install_missing_dependencies(["curl"], "debian")


# ---------------------------------------------------------------------------
# Tests: check_docker_daemon
# ---------------------------------------------------------------------------


class TestCheckDockerDaemon:
    @patch("vpn007.prerequisites.subprocess.run")
    def test_docker_running(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        assert check_docker_daemon() is True

    @patch("vpn007.prerequisites.subprocess.run")
    def test_docker_not_running(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1)
        assert check_docker_daemon() is False

    @patch(
        "vpn007.prerequisites.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_docker_not_installed(self, mock_run: MagicMock) -> None:
        assert check_docker_daemon() is False

    @patch(
        "vpn007.prerequisites.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="docker info", timeout=15),
    )
    def test_docker_timeout(self, mock_run: MagicMock) -> None:
        assert check_docker_daemon() is False


# ---------------------------------------------------------------------------
# Tests: check_kernel_capabilities
# ---------------------------------------------------------------------------

_PROC_STATUS_FULL_CAPS = "Name:\tinit\nCapBnd:\t000001ffffffffff\n"
_PROC_STATUS_NO_NET_ADMIN = "Name:\tinit\nCapBnd:\t000001ffffffefff\n"
_PROC_STATUS_NO_SYS_MODULE = "Name:\tinit\nCapBnd:\t000001fffffeffff\n"


class TestCheckKernelCapabilities:
    @patch("vpn007.prerequisites.Path.exists", return_value=True)
    @patch("vpn007.prerequisites.Path.read_text", return_value=_PROC_STATUS_FULL_CAPS)
    def test_all_capabilities_present(
        self, mock_read: MagicMock, mock_exists: MagicMock
    ) -> None:
        warnings = check_kernel_capabilities()
        assert warnings == []

    @patch("vpn007.prerequisites.Path.exists", return_value=False)
    @patch("vpn007.prerequisites.Path.read_text", return_value=_PROC_STATUS_FULL_CAPS)
    def test_tun_device_missing(
        self, mock_read: MagicMock, mock_exists: MagicMock
    ) -> None:
        warnings = check_kernel_capabilities()
        assert any("/dev/net/tun" in w for w in warnings)

    @patch("vpn007.prerequisites.Path.exists", return_value=True)
    @patch(
        "vpn007.prerequisites.Path.read_text",
        return_value=_PROC_STATUS_NO_NET_ADMIN,
    )
    def test_net_admin_missing(
        self, mock_read: MagicMock, mock_exists: MagicMock
    ) -> None:
        warnings = check_kernel_capabilities()
        assert any("NET_ADMIN" in w for w in warnings)

    @patch("vpn007.prerequisites.Path.exists", return_value=True)
    @patch(
        "vpn007.prerequisites.Path.read_text",
        return_value=_PROC_STATUS_NO_SYS_MODULE,
    )
    def test_sys_module_missing(
        self, mock_read: MagicMock, mock_exists: MagicMock
    ) -> None:
        warnings = check_kernel_capabilities()
        assert any("SYS_MODULE" in w for w in warnings)

    @patch("vpn007.prerequisites.Path.exists", return_value=True)
    @patch("vpn007.prerequisites.Path.read_text", return_value=_PROC_STATUS_FULL_CAPS)
    def test_alpine_skips_kernel_headers(
        self, mock_read: MagicMock, mock_exists: MagicMock
    ) -> None:
        warnings = check_kernel_capabilities(distro="alpine")
        assert any("amneziawg-go" in w.lower() for w in warnings)
        assert any("Alpine" in w for w in warnings)

    @patch("vpn007.prerequisites.Path.exists", return_value=True)
    @patch("vpn007.prerequisites.Path.read_text", return_value=_PROC_STATUS_FULL_CAPS)
    def test_non_alpine_no_userspace_note(
        self, mock_read: MagicMock, mock_exists: MagicMock
    ) -> None:
        warnings = check_kernel_capabilities(distro="debian")
        assert not any("amneziawg-go" in w.lower() for w in warnings)

    @patch("vpn007.prerequisites.Path.exists", return_value=True)
    @patch(
        "vpn007.prerequisites.Path.read_text",
        side_effect=FileNotFoundError("/proc/1/status not found"),
    )
    def test_proc_status_unreadable(
        self, mock_read: MagicMock, mock_exists: MagicMock
    ) -> None:
        warnings = check_kernel_capabilities()
        assert any("Could not read" in w for w in warnings)


# ---------------------------------------------------------------------------
# Tests: check_system_resources
# ---------------------------------------------------------------------------

_MEMINFO_4GB = "MemTotal:        4194304 kB\nMemFree:         2097152 kB\n"
_MEMINFO_1GB = "MemTotal:        1048576 kB\nMemFree:          524288 kB\n"


class TestCheckSystemResources:
    @patch("vpn007.prerequisites.subprocess.run")
    @patch("vpn007.prerequisites.Path.read_text", return_value=_MEMINFO_4GB)
    def test_sufficient_resources(
        self, mock_read: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Avail\n21474836480\n",  # 20 GB
        )
        warnings = check_system_resources()
        assert warnings == []

    @patch("vpn007.prerequisites.subprocess.run")
    @patch("vpn007.prerequisites.Path.read_text", return_value=_MEMINFO_1GB)
    def test_insufficient_ram(
        self, mock_read: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Avail\n21474836480\n",
        )
        warnings = check_system_resources()
        assert any("Insufficient RAM" in w for w in warnings)

    @patch("vpn007.prerequisites.subprocess.run")
    @patch("vpn007.prerequisites.Path.read_text", return_value=_MEMINFO_4GB)
    def test_insufficient_disk(
        self, mock_read: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Avail\n5368709120\n",  # 5 GB
        )
        warnings = check_system_resources()
        assert any("Insufficient disk" in w for w in warnings)

    @patch(
        "vpn007.prerequisites.subprocess.run",
        side_effect=FileNotFoundError,
    )
    @patch(
        "vpn007.prerequisites.Path.read_text",
        side_effect=FileNotFoundError,
    )
    def test_unreadable_resources(
        self, mock_read: MagicMock, mock_run: MagicMock
    ) -> None:
        warnings = check_system_resources()
        assert any("Could not read" in w for w in warnings)
        assert any("Could not check" in w for w in warnings)


# ---------------------------------------------------------------------------
# Tests: run_prerequisite_checks (orchestrator)
# ---------------------------------------------------------------------------


class TestRunPrerequisiteChecks:
    @patch("vpn007.prerequisites.check_system_resources", return_value=[])
    @patch("vpn007.prerequisites.check_kernel_capabilities", return_value=[])
    @patch("vpn007.prerequisites.check_docker_daemon", return_value=True)
    @patch("vpn007.prerequisites.install_missing_dependencies")
    @patch("vpn007.prerequisites.get_missing_dependencies", return_value=[])
    @patch(
        "vpn007.prerequisites.check_dependencies",
        return_value={
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": "3.14.0",
            "nftables": "1.0.6",
            "curl": "8.4.0",
            "git": "2.43.0",
        },
    )
    @patch("vpn007.prerequisites.validate_os", return_value=[])
    @patch("vpn007.prerequisites.detect_os", return_value=("ubuntu", "22.04"))
    def test_all_checks_pass(self, *mocks: MagicMock) -> None:
        ok, messages = run_prerequisite_checks()
        assert ok is True
        assert any("Detected OS" in m for m in messages)
        assert any("Docker daemon: running" in m for m in messages)

    @patch("vpn007.prerequisites.check_system_resources", return_value=[])
    @patch("vpn007.prerequisites.check_kernel_capabilities", return_value=[])
    @patch("vpn007.prerequisites.check_docker_daemon", return_value=False)
    @patch("vpn007.prerequisites.get_missing_dependencies", return_value=[])
    @patch(
        "vpn007.prerequisites.check_dependencies",
        return_value={
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": "3.14.0",
            "nftables": "1.0.6",
            "curl": "8.4.0",
            "git": "2.43.0",
        },
    )
    @patch("vpn007.prerequisites.validate_os", return_value=[])
    @patch("vpn007.prerequisites.detect_os", return_value=("debian", "12"))
    def test_docker_not_running_fails(self, *mocks: MagicMock) -> None:
        ok, messages = run_prerequisite_checks()
        assert ok is False
        assert any("Docker daemon is not running" in m for m in messages)

    @patch("vpn007.prerequisites.check_system_resources", return_value=[])
    @patch("vpn007.prerequisites.check_kernel_capabilities", return_value=[])
    @patch("vpn007.prerequisites.check_docker_daemon", return_value=True)
    @patch("vpn007.prerequisites.get_missing_dependencies", return_value=[])
    @patch(
        "vpn007.prerequisites.check_dependencies",
        return_value={
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": "3.14.0",
            "nftables": "1.0.6",
            "curl": "8.4.0",
            "git": "2.43.0",
        },
    )
    @patch(
        "vpn007.prerequisites.validate_os",
        return_value=["Unsupported OS: fedora 39"],
    )
    @patch("vpn007.prerequisites.detect_os", return_value=("fedora", "39"))
    def test_unsupported_os_fails(self, *mocks: MagicMock) -> None:
        ok, messages = run_prerequisite_checks()
        assert ok is False
        assert any("Unsupported OS" in m for m in messages)

    @patch("vpn007.prerequisites.check_system_resources", return_value=[])
    @patch(
        "vpn007.prerequisites.check_kernel_capabilities",
        return_value=["WARNING: /dev/net/tun is not available."],
    )
    @patch("vpn007.prerequisites.check_docker_daemon", return_value=True)
    @patch("vpn007.prerequisites.get_missing_dependencies", return_value=[])
    @patch(
        "vpn007.prerequisites.check_dependencies",
        return_value={
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": "3.14.0",
            "nftables": "1.0.6",
            "curl": "8.4.0",
            "git": "2.43.0",
        },
    )
    @patch("vpn007.prerequisites.validate_os", return_value=[])
    @patch("vpn007.prerequisites.detect_os", return_value=("ubuntu", "22.04"))
    def test_kernel_warnings_included(self, *mocks: MagicMock) -> None:
        ok, messages = run_prerequisite_checks()
        # Kernel warnings don't cause failure, just warnings
        assert ok is True
        assert any("WARNING" in m for m in messages)

    @patch("vpn007.prerequisites.check_system_resources", return_value=[])
    @patch("vpn007.prerequisites.check_kernel_capabilities", return_value=[])
    @patch("vpn007.prerequisites.check_docker_daemon", return_value=True)
    @patch("vpn007.prerequisites.install_missing_dependencies")
    @patch(
        "vpn007.prerequisites.get_missing_dependencies",
        return_value=["curl", "git"],
    )
    @patch(
        "vpn007.prerequisites.check_dependencies",
        return_value={
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": "3.14.0",
            "nftables": "1.0.6",
            "curl": None,
            "git": None,
        },
    )
    @patch("vpn007.prerequisites.validate_os", return_value=[])
    @patch("vpn007.prerequisites.detect_os", return_value=("ubuntu", "22.04"))
    def test_missing_deps_triggers_install(self, *mocks: MagicMock) -> None:
        ok, messages = run_prerequisite_checks()
        assert ok is True
        assert any("Missing or outdated" in m for m in messages)
        assert any("Successfully installed" in m for m in messages)

    @patch("vpn007.prerequisites.check_system_resources", return_value=[])
    @patch("vpn007.prerequisites.check_kernel_capabilities", return_value=[])
    @patch("vpn007.prerequisites.check_docker_daemon", return_value=True)
    @patch(
        "vpn007.prerequisites.install_missing_dependencies",
        side_effect=subprocess.CalledProcessError(1, "apt-get"),
    )
    @patch(
        "vpn007.prerequisites.get_missing_dependencies",
        return_value=["curl"],
    )
    @patch(
        "vpn007.prerequisites.check_dependencies",
        return_value={
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": "3.14.0",
            "nftables": "1.0.6",
            "curl": None,
            "git": "2.43.0",
        },
    )
    @patch("vpn007.prerequisites.validate_os", return_value=[])
    @patch("vpn007.prerequisites.detect_os", return_value=("debian", "12"))
    def test_install_failure_sets_ok_false(self, *mocks: MagicMock) -> None:
        ok, messages = run_prerequisite_checks()
        assert ok is False
        assert any("Failed to install" in m for m in messages)

    @patch("vpn007.prerequisites.check_system_resources", return_value=[])
    @patch("vpn007.prerequisites.check_kernel_capabilities", return_value=[])
    @patch("vpn007.prerequisites.check_docker_daemon", return_value=True)
    @patch("vpn007.prerequisites.get_missing_dependencies", return_value=[])
    @patch(
        "vpn007.prerequisites.check_dependencies",
        return_value={
            "docker": "24.0.7",
            "docker-compose": "2.24.5",
            "python3": "3.14.0",
            "nftables": "1.0.6",
            "curl": "8.4.0",
            "git": "2.43.0",
        },
    )
    @patch("vpn007.prerequisites.validate_os", return_value=[])
    @patch(
        "vpn007.prerequisites.detect_os",
        side_effect=FileNotFoundError("/etc/os-release not found"),
    )
    def test_os_detection_failure(self, *mocks: MagicMock) -> None:
        ok, messages = run_prerequisite_checks()
        assert ok is False
        assert any("OS detection failed" in m for m in messages)
