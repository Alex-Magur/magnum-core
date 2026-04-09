import ipaddress
import pytest
from sandbox.config import SandboxSettings, SandboxPolicy


def test_sandbox_settings_defaults():
    """Verify that SandboxSettings loads default ADR 3.1 values correctly."""
    settings = SandboxSettings()
    assert settings.workspace_path == "/workspace"
    assert "GET" in settings.allowed_methods
    assert "POST" in settings.allowed_methods
    assert "api.github.com" in settings.allowed_hosts
    assert settings.deny_ip_literals is True
    assert settings.jit_token_ttl_seconds == 60


def test_sandbox_settings_env_override(monkeypatch):
    """Verify that environment variables correctly override defaults."""
    monkeypatch.setenv("SANDBOX_WORKSPACE_PATH", "/tmp/sandbox")
    monkeypatch.setenv("SANDBOX_ALLOWED_HOSTS", '["example.com", "google.com"]')
    
    settings = SandboxSettings()
    assert settings.workspace_path == "/tmp/sandbox"
    assert "example.com" in settings.allowed_hosts
    assert "google.com" in settings.allowed_hosts


def test_sandbox_policy_compilation():
    """Verify that SandboxPolicy pre-compiles CIDRs and normalizes methods/hosts."""
    settings = SandboxSettings(
        allowed_methods=["get", "Patch"],
        allowed_hosts=["API.GitHub.Com"]
    )
    policy = SandboxPolicy.from_settings(settings)
    
    # Normalization
    assert "GET" in policy.allowed_methods
    assert "PATCH" in policy.allowed_methods
    assert "api.github.com" in policy.allowed_hosts
    
    # CIDR compilation
    assert len(policy.deny_networks) > 0
    assert all(isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)) for net in policy.deny_networks)
    
    # Check for loopback (implicit deny)
    loopback_v4 = ipaddress.ip_network("127.0.0.0/8")
    assert loopback_v4 in policy.deny_networks


def test_is_private_address():
    """Verify the private address detection logic with strings and IP objects."""
    policy = SandboxPolicy.from_settings(SandboxSettings())
    
    # IPv4 Private
    assert policy.is_private_address("127.0.0.1") is True
    assert policy.is_private_address("10.0.0.5") is True
    assert policy.is_private_address("192.168.1.100") is True
    assert policy.is_private_address(ipaddress.IPv4Address("172.16.0.1")) is True
    
    # IPv6 Private/Loopback
    assert policy.is_private_address("::1") is True
    assert policy.is_private_address("fc00::1") is True
    
    # Public
    assert policy.is_private_address("8.8.8.8") is False
    assert policy.is_private_address("1.1.1.1") is False
    assert policy.is_private_address(ipaddress.IPv4Address("20.20.20.20")) is False
