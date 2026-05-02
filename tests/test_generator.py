# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Unit tests for the VPN007 generator orchestrator."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from vpn007.generator import (
    generate_all,
    generate_deployment_summary,
    generate_initial_approved_ips_conf,
)
from vpn007.models import DeployConfig, RealityKeys, TunnelType, PortForward

from tests.conftest import valid_awg_obfuscation, valid_deploy_config


class TestGenerateInitialApprovedIpsConf:
    """Tests for generate_initial_approved_ips_conf."""

    def test_with_approved_ips(self, valid_config: DeployConfig) -> None:
        """Static approved IPs produce allow directives."""
        config = valid_config
        config.approved_ips = ["10.0.0.1", "192.168.1.0/24"]
        result = generate_initial_approved_ips_conf(config)
        assert "allow 10.0.0.1;" in result
        assert "allow 192.168.1.0/24;" in result

    def test_empty_approved_ips(self, valid_config: DeployConfig) -> None:
        """Empty approved_ips produces a comment placeholder."""
        config = valid_config
        config.approved_ips = []
        result = generate_initial_approved_ips_conf(config)
        assert "allow" not in result.replace("# No static approved IPs configured.", "")
        assert "No static approved IPs" in result

    def test_contains_copyright(self, valid_config: DeployConfig) -> None:
        """Output includes the copyright notice."""
        result = generate_initial_approved_ips_conf(valid_config)
        assert "Vadim Pavlov 2026" in result

    def test_single_ip(self, valid_config: DeployConfig) -> None:
        """Single IP produces exactly one allow directive."""
        config = valid_config
        config.approved_ips = ["1.2.3.4"]
        result = generate_initial_approved_ips_conf(config)
        assert result.count("allow ") == 1
        assert "allow 1.2.3.4;" in result


class TestGenerateAll:
    """Tests for generate_all orchestrator."""

    def test_creates_output_directories(self, tmp_path: Path) -> None:
        """generate_all creates all required subdirectories."""
        config = DeployConfig(domain="vpn.example.com", output_dir=tmp_path)
        generate_all(config)

        for subdir in ["nginx", "xray", "scripts", "systemd", "docs", "clients"]:
            assert (tmp_path / subdir).is_dir(), f"Missing directory: {subdir}"

    def test_returns_dict_of_files(self, tmp_path: Path) -> None:
        """generate_all returns a dict mapping relative paths to content."""
        config = DeployConfig(domain="vpn.example.com", output_dir=tmp_path)
        files = generate_all(config)

        assert isinstance(files, dict)
        assert len(files) > 0
        for key, value in files.items():
            assert isinstance(key, str)
            assert isinstance(value, str)
            assert len(value) > 0

    def test_core_files_present(self, tmp_path: Path) -> None:
        """generate_all produces all core deployment files."""
        config = DeployConfig(domain="vpn.example.com", output_dir=tmp_path)
        files = generate_all(config)

        expected_keys = [
            "docker-compose.yml",
            "nginx/stream.conf",
            "nginx/http.conf",
            "nginx/approved_panel_ips.conf",
            "xray/config.json",
            "nftables.conf",
            "scripts/blocklist-updater.sh",
            "systemd/blocklist-updater.service",
            "systemd/blocklist-updater.timer",
            "scripts/hostname-resolver.sh",
            "systemd/hostname-resolver.service",
            "systemd/hostname-resolver.timer",
            "scripts/certbot-renew.sh",
            "systemd/certbot-renew.service",
            "systemd/certbot-renew.timer",
            "docs/README.md",
            "docs/troubleshooting.md",
            "docs/client-guides.md",
        ]
        for key in expected_keys:
            assert key in files, f"Missing file: {key}"

    def test_files_written_to_disk(self, tmp_path: Path) -> None:
        """generate_all writes all files to the output directory."""
        config = DeployConfig(domain="vpn.example.com", output_dir=tmp_path)
        files = generate_all(config)

        for rel_path, content in files.items():
            full_path = tmp_path / rel_path
            assert full_path.exists(), f"File not written: {rel_path}"
            assert full_path.read_text(encoding="utf-8") == content

    def test_xray_client_file_generated(self, tmp_path: Path) -> None:
        """generate_all creates an Xray client config file."""
        config = DeployConfig(domain="vpn.example.com", output_dir=tmp_path)
        files = generate_all(config)

        client_files = [k for k in files if k.startswith("clients/xray-")]
        assert len(client_files) == 1
        assert client_files[0].endswith(".txt")

    def test_approved_ips_conf_written(self, tmp_path: Path) -> None:
        """approved_panel_ips.conf is written with allow directives."""
        config = DeployConfig(
            domain="vpn.example.com",
            output_dir=tmp_path,
            approved_ips=["10.0.0.1", "172.16.0.0/12"],
        )
        files = generate_all(config)

        conf = files["nginx/approved_panel_ips.conf"]
        assert "allow 10.0.0.1;" in conf
        assert "allow 172.16.0.0/12;" in conf

    def test_forwarding_script_not_generated_when_disabled(
        self, tmp_path: Path
    ) -> None:
        """forwarding-install.py is NOT generated when forwarding is disabled."""
        config = DeployConfig(
            domain="vpn.example.com",
            output_dir=tmp_path,
            forwarding_enabled=False,
        )
        files = generate_all(config)
        assert "forwarding-install.py" not in files

    def test_forwarding_script_generated_when_enabled(
        self, tmp_path: Path
    ) -> None:
        """forwarding-install.py IS generated when forwarding is enabled."""
        config = DeployConfig(
            domain="vpn.example.com",
            output_dir=tmp_path,
            forwarding_enabled=True,
            tunnel_type=TunnelType.WIREGUARD,
            secondary_vm_ip="10.0.0.2",
            forwarding_ports=[
                PortForward(
                    protocol="tcp", listen_port=443, forward_port=443
                ),
            ],
        )
        files = generate_all(config)
        assert "forwarding-install.py" in files
        assert (tmp_path / "forwarding-install.py").exists()

    def test_certbot_renew_files_generated(self, tmp_path: Path) -> None:
        """Certbot renewal script and systemd units are generated."""
        config = DeployConfig(domain="vpn.example.com", output_dir=tmp_path)
        files = generate_all(config)

        assert "scripts/certbot-renew.sh" in files
        assert "systemd/certbot-renew.service" in files
        assert "systemd/certbot-renew.timer" in files

    def test_docs_files_generated(self, tmp_path: Path) -> None:
        """Documentation files are generated in the docs/ subdirectory."""
        config = DeployConfig(domain="vpn.example.com", output_dir=tmp_path)
        files = generate_all(config)

        assert "docs/README.md" in files
        assert "docs/troubleshooting.md" in files
        assert "docs/client-guides.md" in files


class TestGenerateDeploymentSummary:
    """Tests for generate_deployment_summary."""

    def test_summary_contains_endpoints(self, tmp_path: Path) -> None:
        """Summary includes service endpoint URLs."""
        config = DeployConfig(
            domain="vpn.example.com",
            output_dir=tmp_path,
            public_ipv4="203.0.113.10",
            awg_listen_port=34567,
        )
        files = {"docker-compose.yml": "content"}
        summary = generate_deployment_summary(config, files)

        assert "203.0.113.10" in summary
        assert config.xui_path_prefix in summary
        assert config.awg_panel_path_prefix in summary
        assert "34567" in summary

    def test_summary_contains_generated_files(self, tmp_path: Path) -> None:
        """Summary lists generated file paths."""
        config = DeployConfig(domain="vpn.example.com", output_dir=tmp_path)
        files = {
            "docker-compose.yml": "content",
            "nginx/stream.conf": "content",
        }
        summary = generate_deployment_summary(config, files)

        assert "docker-compose.yml" in summary
        assert "nginx/stream.conf" in summary

    def test_summary_shows_approved_ips(self, tmp_path: Path) -> None:
        """Summary lists approved panel IPs when configured."""
        config = DeployConfig(
            domain="vpn.example.com",
            output_dir=tmp_path,
            approved_ips=["10.0.0.1"],
        )
        summary = generate_deployment_summary(config, {})
        assert "10.0.0.1" in summary

    def test_summary_optional_8443(self, tmp_path: Path) -> None:
        """Summary includes port 8443 only when enabled."""
        config_off = DeployConfig(
            domain="vpn.example.com",
            output_dir=tmp_path,
            enable_port_8443=False,
        )
        summary_off = generate_deployment_summary(config_off, {})
        assert "8443" not in summary_off

        config_on = DeployConfig(
            domain="vpn.example.com",
            output_dir=tmp_path,
            enable_port_8443=True,
        )
        summary_on = generate_deployment_summary(config_on, {})
        assert "8443" in summary_on

    def test_summary_uses_domain_when_no_ip(self, tmp_path: Path) -> None:
        """Summary falls back to domain when no public IP is set."""
        config = DeployConfig(
            domain="vpn.example.com",
            output_dir=tmp_path,
        )
        summary = generate_deployment_summary(config, {})
        assert "vpn.example.com" in summary


# ---------------------------------------------------------------------------
# Hypothesis strategy for deterministic DeployConfig (no randomness sources)
# ---------------------------------------------------------------------------

# Strategy for RealityKeys with explicit values
_valid_reality_keys = st.builds(
    RealityKeys,
    private_key=st.from_regex(r"[A-Za-z0-9+/]{43}=", fullmatch=True),
    public_key=st.from_regex(r"[A-Za-z0-9+/]{43}=", fullmatch=True),
    short_id=st.from_regex(r"[0-9a-f]{8}", fullmatch=True),
)


def _deterministic_deploy_config():
    """Strategy producing a DeployConfig with all random fields pinned.

    Ensures awg_obfuscation and reality_keys are always explicit (not None)
    so that generate_all has no internal randomness for the key config files.
    awg_listen_port is already always explicit in valid_deploy_config.
    """
    return st.tuples(
        valid_deploy_config,
        valid_awg_obfuscation,
        _valid_reality_keys,
    ).map(_pin_deterministic_fields)


def _pin_deterministic_fields(
    args: tuple,
) -> DeployConfig:
    """Replace None-valued random fields with explicit values."""
    config, awg_obfuscation, reality_keys = args
    config.awg_obfuscation = awg_obfuscation
    config.reality_keys = reality_keys
    return config


# ---------------------------------------------------------------------------
# Property 14: Idempotent configuration generation
# ---------------------------------------------------------------------------

# Key files that must be byte-identical across two generation runs.
_IDEMPOTENT_FILES = [
    "docker-compose.yml",
    "nginx/stream.conf",
    "nginx/http.conf",
    "xray/config.json",
    "nftables.conf",
]


class TestProperty14IdempotentConfigGeneration:
    """**Property 14: Idempotent configuration generation**

    For any valid DeployConfig, generating all configuration files twice
    with the same input produces byte-identical output for docker-compose.yml,
    nginx configs, nftables config, and xray config.

    **Validates: Requirements 13.2**
    """

    @given(config=_deterministic_deploy_config())
    @settings(max_examples=100)
    def test_idempotent_generation(self, config: DeployConfig) -> None:
        """Generating all files twice with the same config produces identical output."""
        import tempfile

        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            # First generation run
            config1 = replace(config, output_dir=Path(td1))
            files1 = generate_all(config1)

            # Second generation run
            config2 = replace(config, output_dir=Path(td2))
            files2 = generate_all(config2)

            for rel_path in _IDEMPOTENT_FILES:
                assert rel_path in files1, f"Missing {rel_path} in first run"
                assert rel_path in files2, f"Missing {rel_path} in second run"
                assert files1[rel_path] == files2[rel_path], (
                    f"{rel_path} differs between runs"
                )
