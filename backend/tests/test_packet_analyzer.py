
import pytest

from scapy.layers.dns import DNS, DNSQR
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


def test_analyze_tcp_syn_packet():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=54321, dport=22, flags="S")
    )

    result = analyze_packet(packet)

    assert result["tcp_flags"] == "S"


def test_analyze_tcp_syn_ack_packet():
    packet = (
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=22, dport=54321, flags="SA")
    )

    result = analyze_packet(packet)

    assert result["tcp_flags"] == "SA"


def test_non_tcp_packet_has_no_tcp_flags():
    packet = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
    )

    result = analyze_packet(packet)

    assert result["tcp_flags"] is None


def test_analyze_arp_request_details():
    packet = Ether() / ARP(
        op=1,
        hwsrc="00:11:22:33:44:55",
        hwdst="00:00:00:00:00:00",
        psrc="192.168.1.10",
        pdst="192.168.1.1",
    )

    result = analyze_packet(packet)

    assert result["protocol"] == "ARP"
    assert result["arp_operation"] == 1
    assert result["arp_source_mac"] == "00:11:22:33:44:55"
    assert result["arp_destination_mac"] == "00:00:00:00:00:00"


def test_analyze_arp_reply_details():
    packet = Ether() / ARP(
        op=2,
        hwsrc="00:11:22:33:44:66",
        hwdst="00:11:22:33:44:55",
        psrc="192.168.1.1",
        pdst="192.168.1.10",
    )

    result = analyze_packet(packet)

    assert result["protocol"] == "ARP"
    assert result["arp_operation"] == 2
    assert result["arp_source_mac"] == "00:11:22:33:44:66"
    assert result["arp_destination_mac"] == "00:11:22:33:44:55"


def test_non_arp_packet_has_no_arp_details():
    packet = IP(
        src="192.168.1.10",
        dst="8.8.8.8",
    ) / UDP(sport=53000, dport=53)

    result = analyze_packet(packet)

    assert result["arp_operation"] is None
    assert result["arp_source_mac"] is None
    assert result["arp_destination_mac"] is None


def test_analyze_dns_query():
    packet = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(
            qr=0,
            qd=DNSQR(qname="example.com", qtype="A"),
        )
    )

    result = analyze_packet(packet)

    assert result["protocol"] == "DNS"
    assert result["transport_protocol"] == "UDP"
    assert result["dns_query_name"] == "example.com"
    assert result["dns_query_type"] == 1
    assert result["dns_is_response"] is False
    assert result["dns_response_code"] == 0


def test_analyze_dns_response():
    packet = (
        IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=53000)
        / DNS(
            qr=1,
            rcode=3,
            qd=DNSQR(qname="missing.example", qtype="A"),
        )
    )

    result = analyze_packet(packet)

    assert result["protocol"] == "DNS"
    assert result["dns_query_name"] == "missing.example"
    assert result["dns_is_response"] is True
    assert result["dns_response_code"] == 3
    assert result["dns_answer_count"] == 0


def test_analyze_dns_over_tcp():
    packet = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=53000, dport=53)
        / DNS(
            qr=0,
            qd=DNSQR(qname="example.org", qtype="AAAA"),
        )
    )

    result = analyze_packet(packet)

    assert result["protocol"] == "DNS"
    assert result["transport_protocol"] == "TCP"
    assert result["dns_query_name"] == "example.org"
    assert result["dns_query_type"] == 28


def test_non_dns_packet_has_no_dns_details():
    packet = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
    )

    result = analyze_packet(packet)

    assert result["protocol"] == "UDP"
    assert result["dns_query_name"] is None
    assert result["dns_query_type"] is None
    assert result["dns_is_response"] is None
    assert result["dns_response_code"] is None
    assert result["dns_answer_count"] is None
