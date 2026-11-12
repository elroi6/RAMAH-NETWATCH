import pytest

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.services.packet_analyzer import analyze_packet


def test_analyze_tcp_packet():
    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=54321, dport=443)
    )

    result = analyze_packet(packet)

    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "192.168.1.20"
    assert result["source_port"] == 54321
    assert result["destination_port"] == 443
    assert result["protocol"] == "TCP"
    assert result["packet_size"] == len(packet)


def test_analyze_udp_packet():
    packet = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
    )

    result = analyze_packet(packet)

    assert result["protocol"] == "UDP"
    assert result["source_port"] == 53000
    assert result["destination_port"] == 53


def test_analyze_icmp_packet():
    packet = IP(
        src="192.168.1.10",
        dst="192.168.1.1"
    ) / ICMP()

    result = analyze_packet(packet)

    assert result["protocol"] == "ICMP"
    assert result["source_port"] is None
    assert result["destination_port"] is None


def test_analyze_arp_packet():
    packet = Ether() / ARP(
        op=1,
        psrc="192.168.1.10",
        pdst="192.168.1.1"
    )

    result = analyze_packet(packet)

    assert result["protocol"] == "ARP"
    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "192.168.1.1"


def test_analyze_ipv6_tcp_packet():
    packet = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=12345, dport=443)
    )

    result = analyze_packet(packet)

    assert result["source_ip"] == "2001:db8::1"
    assert result["destination_ip"] == "2001:db8::2"
    assert result["protocol"] == "TCP"


def test_analyze_other_ip_packet():
    packet = IP(
        src="192.168.1.10",
        dst="192.168.1.20",
        proto=47
    ) / Raw(load=b"test")

    result = analyze_packet(packet)

    assert result["protocol"] == "OTHER"
    assert result["source_port"] is None
    assert result["destination_port"] is None


def test_analyze_packet_rejects_invalid_input():
    with pytest.raises(TypeError):
        analyze_packet("not a packet")
def test_analyze_ipv6_icmp_echo_request():
    packet = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / ICMPv6EchoRequest()
    )

    result = analyze_packet(packet)

    assert result["source_ip"] == "2001:db8::1"
    assert result["destination_ip"] == "2001:db8::2"
    assert result["protocol"] == "ICMP"
    assert result["source_port"] is None
    assert result["destination_port"] is None


def test_analyze_ipv6_icmp_echo_reply():
    packet = (
        IPv6(src="2001:db8::2", dst="2001:db8::1")
        / ICMPv6EchoReply()
    )

    result = analyze_packet(packet)

    assert result["source_ip"] == "2001:db8::2"
    assert result["destination_ip"] == "2001:db8::1"
    assert result["protocol"] == "ICMP"
    assert result["source_port"] is None
    assert result["destination_port"] is None
