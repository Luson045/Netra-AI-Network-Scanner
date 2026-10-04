"""Tests for target parsing and authorization guardrails."""

import ipaddress

import pytest

from app.core.errors import TargetNotAuthorizedError, ValidationError
from app.services.scanner.targets import parse_port_spec, parse_targets


class TestParsePortSpec:
    def test_default_ports_when_none(self):
        ports = parse_port_spec(None)
        assert 80 in ports and 443 in ports and 22 in ports

    def test_simple_list(self):
        assert parse_port_spec("22,80,443") == [22, 80, 443]

    def test_range(self):
        assert parse_port_spec("8000-8003") == [8000, 8001, 8002, 8003]

    def test_mixed_dedup_and_sort(self):
        assert parse_port_spec("443,80,80,8100-8102") == [80, 443, 8100, 8101, 8102]

    def test_rejects_out_of_bounds(self):
        with pytest.raises(ValidationError):
            parse_port_spec("70000")

    def test_rejects_garbage(self):
        with pytest.raises(ValidationError):
            parse_port_spec("http")


class TestParseTargets:
    def test_single_loopback(self):
        nets, hosts = parse_targets("127.0.0.1")
        assert hosts == [ipaddress.ip_address("127.0.0.1")]
        assert nets == ["127.0.0.1"]

    def test_private_subnet(self):
        nets, hosts = parse_targets("192.168.1.0/30")
        assert len(hosts) == 2  # .1 and .2 (network/broadcast excluded)
        assert all(ipaddress.ip_address("192.168.1.0") <= h <= ipaddress.ip_address("192.168.1.3") for h in hosts)

    def test_hostname_localhost(self):
        nets, hosts = parse_targets("localhost")
        assert len(hosts) == 1

    def test_rejects_public_ip(self):
        with pytest.raises(TargetNotAuthorizedError):
            parse_targets("8.8.8.8")

    def test_rejects_unresolvable_host(self):
        with pytest.raises(ValidationError):
            parse_targets("definitely-not-a-real-host-name-xyz")

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            parse_targets("")

    def test_rejects_invalid_cidr(self):
        with pytest.raises(ValidationError):
            parse_targets("192.168.1.5/33")

    def test_dedup(self):
        nets, hosts = parse_targets("127.0.0.1, 127.0.0.1")
        assert len(hosts) == 1
