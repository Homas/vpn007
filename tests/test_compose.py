# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Property-based and unit tests for vpn007.compose — Docker Compose generation."""

from __future__ import annotations

import yaml
from hypothesis import given

from vpn007.compose import generate_compose
from vpn007.models import AwgObfuscation, CoverSiteMode, DeployConfig

from tests.conftest import valid_awg_obfuscation, valid_deploy_config


# ---------------------------------------------------------------------------
# Property 3: Compose file contains all required services
# ---------------------------------------------------------------------------

# The five long-running services that must always be present.
LONG_RUNNING_SERVICES = frozenset({
    "reverse_proxy",
    "three_x_ui",
    "amneziawg",
    "tailscale",
    "cover_site",
})

# The certbot utility container (not long-running, uses profiles).
UTILITY_SERVICES = frozenset({"certbot"})

ALL_SERVICES = LONG_RUNNING_SERVICES | UTILITY_SERVICES

# Expected Docker images for each service.
EXPECTED_IMAGES = {
    "reverse_proxy": "nginx:mainline-alpine",
    "three_x_ui": "ghcr.io/mhsanaei/3x-ui:latest",
    "amneziawg": "vpn007/amneziawg:2.0",
    "tailscale": "tailscale/tailscale:latest",
    "cover_site": "nginx:alpine",
    "certbot": "certbot/certbot:latest",
}


class TestProperty3ComposeServiceCompleteness:
    """**Property 3: Compose file contains all required services**

    For any valid DeployConfig, the generated docker-compose.yml defines
    exactly 6 service definitions (5 long-running + 1 utility certbot with
    profiles), each with valid image references, and is parseable YAML.
    The generated YAML must NOT contain /var/run/docker.sock in any service
    volume mount.

    **Validates: Requirements 2.7, 18.8**
    """

    @given(config=valid_deploy_config)
    def test_compose_is_parseable_yaml(self, config: DeployConfig) -> None:
        """Generated compose output must be valid, parseable YAML."""
        output = generate_compose(config)
        parsed = yaml.safe_load(output)
        assert isinstance(parsed, dict), "Parsed YAML must be a dict"
        assert "services" in parsed, "YAML must contain 'services' key"

    @given(config=valid_deploy_config)
    def test_compose_has_exactly_six_services(self, config: DeployConfig) -> None:
        """Compose must define exactly 6 services."""
        parsed = yaml.safe_load(generate_compose(config))
        services = set(parsed["services"].keys())
        assert services == ALL_SERVICES, (
            f"Expected services {ALL_SERVICES}, got {services}"
        )

    @given(config=valid_deploy_config)
    def test_compose_services_have_valid_images(self, config: DeployConfig) -> None:
        """Each service must reference the correct Docker image."""
        parsed = yaml.safe_load(generate_compose(config))
        for svc_name, expected_image in EXPECTED_IMAGES.items():
            if svc_name == "amneziawg":
                # Custom build image with build directive
                actual = parsed["services"][svc_name].get("image")
                assert actual == "vpn007/amneziawg:2.0", (
                    f"Service amneziawg: expected 'vpn007/amneziawg:2.0', got {actual!r}"
                )
                build = parsed["services"][svc_name].get("build")
                assert build is not None, "amneziawg must have 'build' directive"
                assert build.get("dockerfile") == "Dockerfile.amneziawg"
            else:
                actual = parsed["services"][svc_name].get("image")
                assert actual == expected_image, (
                    f"Service {svc_name}: expected image {expected_image!r}, got {actual!r}"
                )

    @given(config=valid_deploy_config)
    def test_compose_no_docker_socket_mount(self, config: DeployConfig) -> None:
        """No service must mount /var/run/docker.sock (especially three_x_ui)."""
        output = generate_compose(config)
        assert "/var/run/docker.sock" not in output, (
            "docker-compose.yml must NOT contain /var/run/docker.sock"
        )

    @given(config=valid_deploy_config)
    def test_certbot_has_profiles(self, config: DeployConfig) -> None:
        """Certbot must use profiles so it doesn't start with 'docker compose up'."""
        parsed = yaml.safe_load(generate_compose(config))
        certbot = parsed["services"]["certbot"]
        assert "profiles" in certbot, "certbot must have 'profiles' key"
        assert "certbot" in certbot["profiles"], (
            "certbot profiles must include 'certbot'"
        )

    @given(config=valid_deploy_config)
    def test_long_running_services_have_restart_policy(self, config: DeployConfig) -> None:
        """All long-running services must have restart: unless-stopped."""
        parsed = yaml.safe_load(generate_compose(config))
        for svc_name in LONG_RUNNING_SERVICES:
            svc = parsed["services"][svc_name]
            assert svc.get("restart") == "unless-stopped", (
                f"Service {svc_name} must have restart: unless-stopped"
            )

    @given(config=valid_deploy_config)
    def test_host_network_services_have_capabilities(self, config: DeployConfig) -> None:
        """AmneziaWG and Tailscale must have NET_ADMIN and SYS_MODULE caps."""
        parsed = yaml.safe_load(generate_compose(config))
        for svc_name in ("amneziawg", "tailscale"):
            svc = parsed["services"][svc_name]
            assert svc.get("network_mode") == "host", (
                f"{svc_name} must use host network"
            )
            caps = svc.get("cap_add", [])
            assert "NET_ADMIN" in caps, f"{svc_name} must have NET_ADMIN"
            assert "SYS_MODULE" in caps, f"{svc_name} must have SYS_MODULE"
            devices = svc.get("devices", [])
            assert any("/dev/net/tun" in d for d in devices), (
                f"{svc_name} must map /dev/net/tun"
            )

    @given(config=valid_deploy_config)
    def test_bridge_network_services_have_static_ips(self, config: DeployConfig) -> None:
        """Bridge-network services must have static IPs on vpn_net."""
        parsed = yaml.safe_load(generate_compose(config))
        expected_ips = {
            "reverse_proxy": "172.20.0.2",
            "three_x_ui": "172.20.0.3",
            "cover_site": "172.20.0.4",
        }
        for svc_name, expected_ip in expected_ips.items():
            svc = parsed["services"][svc_name]
            networks = svc.get("networks", {})
            assert "vpn_net" in networks, f"{svc_name} must be on vpn_net"
            actual_ip = networks["vpn_net"].get("ipv4_address")
            assert actual_ip == expected_ip, (
                f"{svc_name}: expected IP {expected_ip}, got {actual_ip}"
            )

    @given(config=valid_deploy_config)
    def test_vpn_net_bridge_network_defined(self, config: DeployConfig) -> None:
        """The vpn_net bridge network must be defined with 172.20.0.0/16 subnet."""
        parsed = yaml.safe_load(generate_compose(config))
        networks = parsed.get("networks", {})
        assert "vpn_net" in networks, "vpn_net network must be defined"
        vpn_net = networks["vpn_net"]
        assert vpn_net.get("driver") == "bridge", "vpn_net must use bridge driver"
        subnets = [
            cfg["subnet"]
            for cfg in vpn_net.get("ipam", {}).get("config", [])
        ]
        assert "172.20.0.0/16" in subnets, (
            f"vpn_net must have 172.20.0.0/16 subnet, got {subnets}"
        )

    @given(config=valid_deploy_config)
    def test_reverse_proxy_has_extra_hosts(self, config: DeployConfig) -> None:
        """reverse_proxy must have host.docker.internal:host-gateway."""
        parsed = yaml.safe_load(generate_compose(config))
        rp = parsed["services"]["reverse_proxy"]
        extra_hosts = rp.get("extra_hosts", [])
        assert any("host.docker.internal" in h for h in extra_hosts), (
            "reverse_proxy must have host.docker.internal extra_host"
        )

    @given(config=valid_deploy_config)
    def test_shared_letsencrypt_volume(self, config: DeployConfig) -> None:
        """Both reverse_proxy and certbot must share the letsencrypt volume."""
        parsed = yaml.safe_load(generate_compose(config))
        for svc_name in ("reverse_proxy", "certbot"):
            svc = parsed["services"][svc_name]
            volumes = svc.get("volumes", [])
            volume_strs = [str(v) for v in volumes]
            assert any("letsencrypt" in v for v in volume_strs), (
                f"{svc_name} must mount the letsencrypt volume"
            )

    @given(config=valid_deploy_config)
    def test_shared_certbot_webroot_volume(self, config: DeployConfig) -> None:
        """Both reverse_proxy and certbot must share the certbot_webroot volume."""
        parsed = yaml.safe_load(generate_compose(config))
        for svc_name in ("reverse_proxy", "certbot"):
            svc = parsed["services"][svc_name]
            volumes = svc.get("volumes", [])
            volume_strs = [str(v) for v in volumes]
            assert any("certbot_webroot" in v for v in volume_strs), (
                f"{svc_name} must mount the certbot_webroot volume"
            )

    @given(config=valid_deploy_config)
    def test_tailscale_persistent_volume(self, config: DeployConfig) -> None:
        """Tailscale must have a persistent volume for /var/lib/tailscale."""
        parsed = yaml.safe_load(generate_compose(config))
        ts = parsed["services"]["tailscale"]
        volumes = ts.get("volumes", [])
        volume_strs = [str(v) for v in volumes]
        assert any("/var/lib/tailscale" in v for v in volume_strs), (
            "tailscale must mount persistent volume at /var/lib/tailscale"
        )

    @given(config=valid_deploy_config)
    def test_three_x_ui_has_data_volume(self, config: DeployConfig) -> None:
        """three_x_ui must have a data volume for Xray configuration."""
        parsed = yaml.safe_load(generate_compose(config))
        svc = parsed["services"]["three_x_ui"]
        volumes = svc.get("volumes", [])
        volume_strs = [str(v) for v in volumes]
        assert any("./data/three_x_ui:/etc/x-ui" in v for v in volume_strs), (
            "three_x_ui must mount ./data/three_x_ui to /etc/x-ui"
        )


# ---------------------------------------------------------------------------
# Unit tests for specific configurations
# ---------------------------------------------------------------------------


class TestComposePort8443:
    """Verify port 8443 is conditionally included."""

    def test_port_8443_included_when_enabled(self) -> None:
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=34567, enable_port_8443=True)
        parsed = yaml.safe_load(generate_compose(config))
        ports = parsed["services"]["reverse_proxy"]["ports"]
        port_strs = [str(p) for p in ports]
        assert any("8443" in p for p in port_strs), "Port 8443 must be present when enabled"

    def test_port_8443_excluded_when_disabled(self) -> None:
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=34567, enable_port_8443=False)
        parsed = yaml.safe_load(generate_compose(config))
        ports = parsed["services"]["reverse_proxy"]["ports"]
        port_strs = [str(p) for p in ports]
        assert not any("8443" in p for p in port_strs), "Port 8443 must not be present when disabled"


class TestComposeIncomingIP:
    """Verify incoming IP binding on ports."""

    def test_incoming_ip_binds_https_port(self) -> None:
        config = DeployConfig(
            domain="vpn.example.com", awg_listen_port=34567, incoming_ip="203.0.113.10"
        )
        parsed = yaml.safe_load(generate_compose(config))
        ports = parsed["services"]["reverse_proxy"]["ports"]
        assert f"203.0.113.10:{config.https_port}:{config.https_port}" in ports

    def test_no_incoming_ip_binds_all(self) -> None:
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=34567)
        parsed = yaml.safe_load(generate_compose(config))
        ports = parsed["services"]["reverse_proxy"]["ports"]
        assert f"{config.https_port}:{config.https_port}" in ports


class TestComposeTailscaleAuthKey:
    """Verify Tailscale auth key is conditionally set."""

    def test_auth_key_present_when_provided(self) -> None:
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            tailscale_auth_key="tskey-auth-test123",
        )
        parsed = yaml.safe_load(generate_compose(config))
        ts_env = parsed["services"]["tailscale"]["environment"]
        assert "TS_AUTHKEY=tskey-auth-test123" in ts_env

    def test_auth_key_absent_when_not_provided(self) -> None:
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=34567)
        parsed = yaml.safe_load(generate_compose(config))
        ts_env = parsed["services"]["tailscale"]["environment"]
        assert not any("TS_AUTHKEY" in str(e) for e in ts_env)


class TestComposeAwgObfuscation:
    """Verify AmneziaWG obfuscation parameters are included."""

    def test_awg_obfuscation_explicit_params_present(self) -> None:
        """When explicit obfuscation params are provided, they appear in env."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            awg_obfuscation=AwgObfuscation(
                s1=30, s2=80, s3=40, s4=100,
                h1=100, h2=200, h3=300, h4=400,
                jc=4, jmin=50, jmax=1000,
                i1=10, i2=20, i3=30, i4=40, i5=50,
            ),
        )
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        assert "AWG_S1=30" in awg_env
        assert "AWG_S4=100" in awg_env
        assert "AWG_H1=100" in awg_env
        assert "AWG_JC=4" in awg_env
        assert "AWG_I5=50" in awg_env

    def test_awg_obfuscation_auto_generated_when_none(self) -> None:
        """When no obfuscation params are provided, they are auto-generated."""
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=34567)
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        # All 2.0 params must be present even when not explicitly provided
        awg_env_str = " ".join(str(e) for e in awg_env)
        for param in ("AWG_S1", "AWG_S2", "AWG_S3", "AWG_S4",
                       "AWG_H1", "AWG_H2", "AWG_H3", "AWG_H4",
                       "AWG_JC", "AWG_JMIN", "AWG_JMAX",
                       "AWG_I1", "AWG_I2", "AWG_I3", "AWG_I4", "AWG_I5"):
            assert param in awg_env_str, (
                f"{param} must be present in auto-generated AWG environment"
            )


class TestComposeAmneziawgConfig:
    """Verify AmneziaWG service has required configuration."""

    def test_amneziawg_no_wg_easy_flags(self) -> None:
        """Custom AmneziaWG 2.0 image should not have wg-easy specific flags."""
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=34567)
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        assert not any("EXPERIMENTAL_AWG" in str(e) for e in awg_env)
        assert not any("OVERRIDE_AUTO_AWG" in str(e) for e in awg_env)

    def test_amneziawg_lib_modules_mount(self) -> None:
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=34567)
        parsed = yaml.safe_load(generate_compose(config))
        volumes = parsed["services"]["amneziawg"]["volumes"]
        assert "/lib/modules:/lib/modules:ro" in volumes

    def test_amneziawg_panel_local_only(self) -> None:
        """AmneziaWG panel must be bound to 127.0.0.1 (local-only)."""
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=34567)
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        assert "WEBUI_HOST=127.0.0.1" in awg_env


class TestComposeAwgPortRandomization:
    """Verify AWG UDP port defaults to a random high port when not specified."""

    def test_awg_port_randomized_when_none(self) -> None:
        """When awg_listen_port is None, a random port in 10000-65535 is used."""
        config = DeployConfig(domain="vpn.example.com")
        assert config.awg_listen_port is None
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        # Find the WG_PORT entry
        wg_port_entries = [e for e in awg_env if str(e).startswith("WG_PORT=")]
        assert len(wg_port_entries) == 1, "Must have exactly one WG_PORT entry"
        port_val = int(str(wg_port_entries[0]).split("=")[1])
        assert 10000 <= port_val <= 65535, (
            f"Random AWG port {port_val} must be in range 10000-65535"
        )

    def test_awg_port_explicit_override(self) -> None:
        """When awg_listen_port is explicitly set, it is used as-is."""
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=51820)
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        assert "WG_PORT=51820" in awg_env

    def test_awg_port_not_standard_wireguard(self) -> None:
        """When port is randomized, it should not be the standard WG port 51820."""
        # Run multiple times to increase confidence (not a guarantee, but
        # the probability of hitting 51820 in 10000-65535 is ~0.002%).
        config = DeployConfig(domain="vpn.example.com")
        ports = set()
        for _ in range(10):
            parsed = yaml.safe_load(generate_compose(config))
            awg_env = parsed["services"]["amneziawg"]["environment"]
            wg_port_entries = [e for e in awg_env if str(e).startswith("WG_PORT=")]
            port_val = int(str(wg_port_entries[0]).split("=")[1])
            ports.add(port_val)
        # At least some variation should exist (extremely unlikely all 10 are the same)
        assert len(ports) > 1, "Random port generation should produce varying ports"


class TestComposeAwg20Validation:
    """Verify the _is_awg_2_0_compatible version checker."""

    def test_version_2_0_compatible(self) -> None:
        from vpn007.compose import _is_awg_2_0_compatible
        assert _is_awg_2_0_compatible("amneziawg-tools v2.0.0") is True
        assert _is_awg_2_0_compatible("2.0.1") is True
        assert _is_awg_2_0_compatible("v2.1.0") is True
        assert _is_awg_2_0_compatible("2.0") is True

    def test_version_1_x_not_compatible(self) -> None:
        from vpn007.compose import _is_awg_2_0_compatible
        assert _is_awg_2_0_compatible("amneziawg-tools v1.0.0") is False
        assert _is_awg_2_0_compatible("1.9.9") is False
        assert _is_awg_2_0_compatible("v1.5.0") is False

    def test_version_empty_not_compatible(self) -> None:
        from vpn007.compose import _is_awg_2_0_compatible
        assert _is_awg_2_0_compatible("") is False
        assert _is_awg_2_0_compatible("unknown") is False


# ---------------------------------------------------------------------------
# Tests for custom AmneziaWG image fallback (Task 10.2)
# Validates: Requirements 4.3, 4.4
# ---------------------------------------------------------------------------


class TestComposeAwgImage:
    """Verify AmneziaWG 2.0 custom image configuration in docker-compose generation."""

    def test_amneziawg_uses_build_directive(self) -> None:
        """amneziawg always uses build from Dockerfile.amneziawg."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
        )
        parsed = yaml.safe_load(generate_compose(config))
        awg = parsed["services"]["amneziawg"]
        assert awg.get("build") is not None, "Must have build directive"
        assert awg["build"]["context"] == "."
        assert awg["build"]["dockerfile"] == "Dockerfile.amneziawg"
        assert awg["image"] == "vpn007/amneziawg:2.0"

    def test_amneziawg_no_experimental_flags(self) -> None:
        """Custom image should not set EXPERIMENTAL_AWG or OVERRIDE_AUTO_AWG."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
        )
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        assert not any("EXPERIMENTAL_AWG" in str(e) for e in awg_env), (
            "Must not set EXPERIMENTAL_AWG"
        )
        assert not any("OVERRIDE_AUTO_AWG" in str(e) for e in awg_env), (
            "Must not set OVERRIDE_AUTO_AWG"
        )

    def test_amneziawg_has_common_env_vars(self) -> None:
        """amneziawg should have WG_HOST, WG_PORT, WEBUI_HOST."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
        )
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        env_str = " ".join(str(e) for e in awg_env)
        assert "WG_HOST=vpn.example.com" in env_str
        assert "WG_PORT=34567" in env_str
        assert "WEBUI_HOST=127.0.0.1" in env_str

    def test_amneziawg_mounts_data_dir(self) -> None:
        """amneziawg should mount data to /etc/amneziawg."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
        )
        parsed = yaml.safe_load(generate_compose(config))
        volumes = parsed["services"]["amneziawg"]["volumes"]
        assert any("/etc/amneziawg" in str(v) for v in volumes), (
            "Must mount data to /etc/amneziawg"
        )

    def test_amneziawg_with_obfuscation_params(self) -> None:
        """amneziawg should include obfuscation env vars when provided."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            awg_obfuscation=AwgObfuscation(
                s1=30, s2=80, s3=40, s4=100,
                h1=100, h2=200, h3=300, h4=400,
                jc=4, jmin=50, jmax=1000,
                i1=10, i2=20, i3=30, i4=40, i5=50,
            ),
        )
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        assert "AWG_S3=40" in awg_env
        assert "AWG_S4=100" in awg_env
        assert "AWG_I5=50" in awg_env

    def test_amneziawg_retains_capabilities(self) -> None:
        """amneziawg must have NET_ADMIN, SYS_MODULE, host network."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
        )
        parsed = yaml.safe_load(generate_compose(config))
        awg = parsed["services"]["amneziawg"]
        assert awg["network_mode"] == "host"
        assert "NET_ADMIN" in awg["cap_add"]
        assert "SYS_MODULE" in awg["cap_add"]


# ---------------------------------------------------------------------------
# Property 6: AmneziaWG obfuscation parameters preserved
# ---------------------------------------------------------------------------

# All 16 AmneziaWG 2.0 obfuscation parameter environment variable names.
AWG_PARAM_NAMES = (
    "AWG_S1", "AWG_S2", "AWG_S3", "AWG_S4",
    "AWG_H1", "AWG_H2", "AWG_H3", "AWG_H4",
    "AWG_I1", "AWG_I2", "AWG_I3", "AWG_I4", "AWG_I5",
    "AWG_JC", "AWG_JMIN", "AWG_JMAX",
)


def _parse_awg_env(awg_env: list[str]) -> dict[str, int]:
    """Parse AmneziaWG environment entries into a name→value mapping."""
    result: dict[str, int] = {}
    for entry in awg_env:
        entry_str = str(entry)
        if entry_str.startswith("AWG_"):
            key, _, val = entry_str.partition("=")
            result[key] = int(val)
    return result


class TestProperty6AwgObfuscationPreserved:
    """**Property 6: AmneziaWG obfuscation parameters preserved**

    For any valid AwgObfuscation, the generated container environment
    contains all 16 AmneziaWG 2.0 obfuscation parameters with the
    specified values. When no obfuscation params are provided, the
    auto-generated values are within valid 2.0 ranges.

    **Validates: Requirements 4.1, 4.5, 4.6**
    """

    @given(awg_obfuscation=valid_awg_obfuscation)
    def test_explicit_obfuscation_params_preserved(
        self, awg_obfuscation: AwgObfuscation
    ) -> None:
        """All 16 explicit AWG params appear in compose env with correct values."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            awg_obfuscation=awg_obfuscation,
        )
        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        env_map = _parse_awg_env(awg_env)

        # All 16 params must be present
        for param in AWG_PARAM_NAMES:
            assert param in env_map, (
                f"{param} missing from AmneziaWG environment"
            )

        # Values must match the input obfuscation object exactly
        assert env_map["AWG_S1"] == awg_obfuscation.s1
        assert env_map["AWG_S2"] == awg_obfuscation.s2
        assert env_map["AWG_S3"] == awg_obfuscation.s3
        assert env_map["AWG_S4"] == awg_obfuscation.s4
        assert env_map["AWG_H1"] == awg_obfuscation.h1
        assert env_map["AWG_H2"] == awg_obfuscation.h2
        assert env_map["AWG_H3"] == awg_obfuscation.h3
        assert env_map["AWG_H4"] == awg_obfuscation.h4
        assert env_map["AWG_I1"] == awg_obfuscation.i1
        assert env_map["AWG_I2"] == awg_obfuscation.i2
        assert env_map["AWG_I3"] == awg_obfuscation.i3
        assert env_map["AWG_I4"] == awg_obfuscation.i4
        assert env_map["AWG_I5"] == awg_obfuscation.i5
        assert env_map["AWG_JC"] == awg_obfuscation.jc
        assert env_map["AWG_JMIN"] == awg_obfuscation.jmin
        assert env_map["AWG_JMAX"] == awg_obfuscation.jmax

    @given(config=valid_deploy_config)
    def test_auto_generated_obfuscation_within_valid_ranges(
        self, config: DeployConfig
    ) -> None:
        """When awg_obfuscation is None, auto-generated values are within valid 2.0 ranges."""
        # Force awg_obfuscation to None so auto-generation kicks in
        from dataclasses import replace

        config = replace(config, awg_obfuscation=None, awg_listen_port=34567)

        parsed = yaml.safe_load(generate_compose(config))
        awg_env = parsed["services"]["amneziawg"]["environment"]
        env_map = _parse_awg_env(awg_env)

        # All 16 params must be present
        for param in AWG_PARAM_NAMES:
            assert param in env_map, (
                f"{param} missing from auto-generated AmneziaWG environment"
            )

        # S1-S4: 15-150
        for s_param in ("AWG_S1", "AWG_S2", "AWG_S3", "AWG_S4"):
            assert 15 <= env_map[s_param] <= 150, (
                f"{s_param}={env_map[s_param]} out of range [15, 150]"
            )

        # Bidirectional S constraints: S1+56≠S2 and S2+56≠S1
        assert env_map["AWG_S1"] + 56 != env_map["AWG_S2"], (
            f"S1+56 must not equal S2: {env_map['AWG_S1']}+56 == {env_map['AWG_S2']}"
        )
        assert env_map["AWG_S2"] + 56 != env_map["AWG_S1"], (
            f"S2+56 must not equal S1: {env_map['AWG_S2']}+56 == {env_map['AWG_S1']}"
        )
        # S3+56≠S4 and S4+56≠S3
        assert env_map["AWG_S3"] + 56 != env_map["AWG_S4"], (
            f"S3+56 must not equal S4: {env_map['AWG_S3']}+56 == {env_map['AWG_S4']}"
        )
        assert env_map["AWG_S4"] + 56 != env_map["AWG_S3"], (
            f"S4+56 must not equal S3: {env_map['AWG_S4']}+56 == {env_map['AWG_S3']}"
        )

        # H1-H4: 5-2147483647, all distinct
        for h_param in ("AWG_H1", "AWG_H2", "AWG_H3", "AWG_H4"):
            assert 5 <= env_map[h_param] <= 2147483647, (
                f"{h_param}={env_map[h_param]} out of range [5, 2147483647]"
            )
        h_values = {env_map[f"AWG_H{i}"] for i in range(1, 5)}
        assert len(h_values) == 4, (
            f"H1-H4 must be distinct, got {[env_map[f'AWG_H{i}'] for i in range(1, 5)]}"
        )

        # I1-I5: 0-1280
        for i_param in ("AWG_I1", "AWG_I2", "AWG_I3", "AWG_I4", "AWG_I5"):
            assert 0 <= env_map[i_param] <= 1280, (
                f"{i_param}={env_map[i_param]} out of range [0, 1280]"
            )

        # Jc: 1-128
        assert 1 <= env_map["AWG_JC"] <= 128, (
            f"AWG_JC={env_map['AWG_JC']} out of range [1, 128]"
        )

        # Jmin <= Jmax, both in [1, 1280]
        assert 1 <= env_map["AWG_JMIN"] <= 1280, (
            f"AWG_JMIN={env_map['AWG_JMIN']} out of range [1, 1280]"
        )
        assert 1 <= env_map["AWG_JMAX"] <= 1280, (
            f"AWG_JMAX={env_map['AWG_JMAX']} out of range [1, 1280]"
        )
        assert env_map["AWG_JMIN"] <= env_map["AWG_JMAX"], (
            f"AWG_JMIN ({env_map['AWG_JMIN']}) must be <= AWG_JMAX ({env_map['AWG_JMAX']})"
        )


# ---------------------------------------------------------------------------
# Property 7: Tailscale service configuration completeness
# ---------------------------------------------------------------------------


class TestProperty7TailscaleConfigCompleteness:
    """**Property 7: Tailscale service configuration completeness**

    For any valid DeployConfig, the Tailscale service has NET_ADMIN and
    SYS_MODULE capabilities, /dev/net/tun device mapping, a persistent
    volume for /var/lib/tailscale, restart: unless-stopped. When a
    tailscale_auth_key is provided, TS_AUTHKEY is set with the correct
    value; when it is None, TS_AUTHKEY is not present.

    **Validates: Requirements 5.2, 5.3**
    """

    @given(config=valid_deploy_config)
    def test_tailscale_has_net_admin_and_sys_module_caps(self, config: DeployConfig) -> None:
        """Tailscale must have NET_ADMIN and SYS_MODULE capabilities."""
        parsed = yaml.safe_load(generate_compose(config))
        ts = parsed["services"]["tailscale"]
        caps = ts.get("cap_add", [])
        assert "NET_ADMIN" in caps, "Tailscale must have NET_ADMIN capability"
        assert "SYS_MODULE" in caps, "Tailscale must have SYS_MODULE capability"

    @given(config=valid_deploy_config)
    def test_tailscale_has_dev_net_tun(self, config: DeployConfig) -> None:
        """Tailscale must map /dev/net/tun device."""
        parsed = yaml.safe_load(generate_compose(config))
        ts = parsed["services"]["tailscale"]
        devices = ts.get("devices", [])
        assert any("/dev/net/tun" in d for d in devices), (
            "Tailscale must map /dev/net/tun device"
        )

    @given(config=valid_deploy_config)
    def test_tailscale_has_persistent_volume(self, config: DeployConfig) -> None:
        """Tailscale must have a persistent volume for /var/lib/tailscale."""
        parsed = yaml.safe_load(generate_compose(config))
        ts = parsed["services"]["tailscale"]
        volumes = ts.get("volumes", [])
        volume_strs = [str(v) for v in volumes]
        assert any("/var/lib/tailscale" in v for v in volume_strs), (
            "Tailscale must mount persistent volume at /var/lib/tailscale"
        )

    @given(config=valid_deploy_config)
    def test_tailscale_has_restart_unless_stopped(self, config: DeployConfig) -> None:
        """Tailscale must have restart: unless-stopped."""
        parsed = yaml.safe_load(generate_compose(config))
        ts = parsed["services"]["tailscale"]
        assert ts.get("restart") == "unless-stopped", (
            "Tailscale must have restart: unless-stopped"
        )

    @given(config=valid_deploy_config)
    def test_tailscale_auth_key_set_when_provided(self, config: DeployConfig) -> None:
        """When tailscale_auth_key is provided, TS_AUTHKEY env var is set with the correct value."""
        from dataclasses import replace

        config = replace(config, tailscale_auth_key="tskey-auth-testkey1234567890")
        parsed = yaml.safe_load(generate_compose(config))
        ts_env = parsed["services"]["tailscale"]["environment"]
        assert "TS_AUTHKEY=tskey-auth-testkey1234567890" in ts_env, (
            "TS_AUTHKEY must be set with the provided auth key value"
        )

    @given(config=valid_deploy_config)
    def test_tailscale_auth_key_absent_when_none(self, config: DeployConfig) -> None:
        """When tailscale_auth_key is None, TS_AUTHKEY must not be present."""
        from dataclasses import replace

        config = replace(config, tailscale_auth_key=None)
        parsed = yaml.safe_load(generate_compose(config))
        ts_env = parsed["services"]["tailscale"]["environment"]
        assert not any("TS_AUTHKEY" in str(e) for e in ts_env), (
            "TS_AUTHKEY must not be present when tailscale_auth_key is None"
        )
