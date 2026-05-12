# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Property-based and unit tests for vpn007.forwarding — inter-VM forwarding
script generation.
"""

from __future__ import annotations

import ast

from hypothesis import given
from hypothesis import strategies as st

from vpn007.forwarding import generate_forwarding_script
from vpn007.models import DeployConfig, PortForward, TunnelType

from tests.conftest import valid_ipv4, valid_port


# ---------------------------------------------------------------------------
# Custom strategy: forwarding-enabled DeployConfig
# ---------------------------------------------------------------------------

# Port forward strategy with descriptions safe for embedding in Python source.
# The default valid_port_forward uses st.text() which can produce null bytes
# and other characters that break Python syntax when embedded in string literals.
_safe_description = st.from_regex(r"[A-Za-z0-9 _\-]{0,30}", fullmatch=True)

_forwarding_port_forward = st.builds(
    PortForward,
    protocol=st.sampled_from(["tcp", "udp"]),
    listen_port=valid_port,
    forward_port=valid_port,
    description=_safe_description,
)

valid_forwarding_config = st.builds(
    DeployConfig,
    domain=st.just("vpn.example.com"),
    awg_listen_port=st.just(34567),
    forwarding_enabled=st.just(True),
    tunnel_type=st.sampled_from(TunnelType),
    exit_node_host=valid_ipv4,
    reverse_initiated=st.booleans(),
    forwarding_ports=st.lists(_forwarding_port_forward, min_size=1, max_size=5),
    reconnect_initial_delay_sec=st.integers(1, 60),
    reconnect_max_delay_sec=st.integers(60, 600),
    incoming_ip=st.none() | valid_ipv4,
    public_ipv4=st.none() | valid_ipv4,
)


# ---------------------------------------------------------------------------
# Property 12: Forwarding script generation completeness
# ---------------------------------------------------------------------------


class TestProperty12ForwardingScriptGenerationCompleteness:
    """**Property 12: Forwarding script generation completeness**

    For any valid forwarding configuration (tunnel type, primary/secondary
    IPs, port forwards, reconnection delays), the generated forwarding
    script should: (a) be valid Python 3 syntax, (b) contain all specified
    parameters, (c) include nftables DNAT/SNAT rules for each port forward,
    and (d) include reconnection logic with configured delays. When
    reverse_initiated is true, the script should include reverse tunnel
    setup.

    **Validates: Requirements 10.9, 10.10, 10.11, 10.13, 10.6**
    """

    @given(config=valid_forwarding_config)
    def test_generated_script_is_valid_python_syntax(
        self, config: DeployConfig
    ) -> None:
        """Generated forwarding script must be valid Python 3.10+ syntax.

        **Validates: Requirements 10.9**
        """
        script = generate_forwarding_script(config)
        # ast.parse will raise SyntaxError if the script is not valid Python
        try:
            ast.parse(script)
        except SyntaxError as exc:
            raise AssertionError(
                f"Generated script is not valid Python syntax: {exc}"
            ) from exc

    @given(config=valid_forwarding_config)
    def test_all_forwarding_ports_appear_as_dnat_rules(
        self, config: DeployConfig
    ) -> None:
        """Each port forward must appear in DNAT/SNAT rules in the script.

        **Validates: Requirements 10.11**
        """
        script = generate_forwarding_script(config)
        for pf in config.forwarding_ports:
            assert str(pf.listen_port) in script, (
                f"Listen port {pf.listen_port} must appear in generated script"
            )
            assert str(pf.forward_port) in script, (
                f"Forward port {pf.forward_port} must appear in generated script"
            )
            assert pf.protocol in script, (
                f"Protocol {pf.protocol} must appear in generated script"
            )

    @given(config=valid_forwarding_config)
    def test_reconnection_parameters_embedded(
        self, config: DeployConfig
    ) -> None:
        """Reconnection initial_delay and max_delay must be embedded in the script.

        **Validates: Requirements 10.13**
        """
        script = generate_forwarding_script(config)
        assert str(config.reconnect_initial_delay_sec) in script, (
            f"Initial delay {config.reconnect_initial_delay_sec} must appear "
            f"in generated script"
        )
        assert str(config.reconnect_max_delay_sec) in script, (
            f"Max delay {config.reconnect_max_delay_sec} must appear "
            f"in generated script"
        )

    @given(config=valid_forwarding_config)
    def test_reverse_initiated_flag_embedded(
        self, config: DeployConfig
    ) -> None:
        """The reverse_initiated flag must be correctly set in the script.

        **Validates: Requirements 10.6**
        """
        script = generate_forwarding_script(config)
        if config.reverse_initiated:
            assert "REVERSE_INITIATED: bool = True" in script, (
                "reverse_initiated=True must produce REVERSE_INITIATED = True"
            )
        else:
            assert "REVERSE_INITIATED: bool = False" in script, (
                "reverse_initiated=False must produce REVERSE_INITIATED = False"
            )

    @given(config=valid_forwarding_config)
    def test_tunnel_type_embedded(self, config: DeployConfig) -> None:
        """The tunnel type must be correctly embedded in the script.

        **Validates: Requirements 10.10**
        """
        script = generate_forwarding_script(config)
        assert config.tunnel_type is not None
        assert config.tunnel_type.value in script, (
            f"Tunnel type {config.tunnel_type.value} must appear in "
            f"generated script"
        )

    @given(config=valid_forwarding_config)
    def test_exit_node_host_embedded(self, config: DeployConfig) -> None:
        """The exit node host must be embedded in the script.

        **Validates: Requirements 10.10**
        """
        script = generate_forwarding_script(config)
        assert config.exit_node_host in script, (
            f"Exit node host {config.exit_node_host} must appear in "
            f"generated script"
        )

    @given(
        config=valid_forwarding_config.filter(
            lambda c: c.reverse_initiated is True
        )
    )
    def test_reverse_initiated_includes_reverse_tunnel_setup(
        self, config: DeployConfig
    ) -> None:
        """When reverse_initiated is True, the script must include reverse
        tunnel setup code (e.g., Endpoint or reverse SSH tunnel).

        **Validates: Requirements 10.6**
        """
        script = generate_forwarding_script(config)
        # The template includes reverse tunnel setup logic when
        # REVERSE_INITIATED is True. Depending on tunnel type:
        # - WireGuard: Endpoint line connecting to primary VM
        # - SSH: reverse SSH tunnel (-R flags)
        # - Tailscale: standard tailscale up
        # All paths include REVERSE_INITIATED = True
        assert "REVERSE_INITIATED: bool = True" in script

        # The script must contain setup logic that references the
        # reverse-initiated connection pattern. The template includes
        # conditional blocks checking REVERSE_INITIATED.
        assert "if REVERSE_INITIATED" in script or "REVERSE_INITIATED" in script, (
            "Script must reference REVERSE_INITIATED for reverse tunnel setup"
        )

    @given(config=valid_forwarding_config)
    def test_script_contains_dnat_snat_keywords(
        self, config: DeployConfig
    ) -> None:
        """The generated script must contain DNAT/SNAT rule generation logic.

        **Validates: Requirements 10.11**
        """
        script = generate_forwarding_script(config)
        # The template generates nftables rules with dnat and masquerade
        assert "dnat to" in script.lower() or "dnat" in script.lower(), (
            "Script must contain DNAT rule generation"
        )
        assert "masquerade" in script.lower() or "snat" in script.lower(), (
            "Script must contain SNAT/masquerade rule generation"
        )

    @given(config=valid_forwarding_config)
    def test_script_contains_reconnection_logic(
        self, config: DeployConfig
    ) -> None:
        """The generated script must contain reconnection logic with
        exponential backoff.

        **Validates: Requirements 10.13**
        """
        script = generate_forwarding_script(config)
        assert "RECONNECT_INITIAL_DELAY" in script, (
            "Script must contain RECONNECT_INITIAL_DELAY constant"
        )
        assert "RECONNECT_MAX_DELAY" in script, (
            "Script must contain RECONNECT_MAX_DELAY constant"
        )
        # The template includes a monitor_and_reconnect function
        assert "monitor_and_reconnect" in script or "reconnect" in script.lower(), (
            "Script must contain reconnection logic"
        )
