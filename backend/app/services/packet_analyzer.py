
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6Unknown
from scapy.layers.l2 import ARP
from scapy.packet import Packet


def analyze_packet(packet: Packet):
    if not isinstance(packet, Packet):
        raise TypeError("Expected a Scapy packet.")

    source_ip = None
    destination_ip = None
    source_port = None
    destination_port = None
    tcp_flags = None
    transport_protocol = None

    arp_operation = None
    arp_source_mac = None
    arp_destination_mac = None

    dns_query_name = None
    dns_query_type = None
    dns_is_response = None
    dns_response_code = None
    dns_answer_count = None

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        source_ip = arp_layer.psrc
        destination_ip = arp_layer.pdst
        arp_operation = int(arp_layer.op)
        arp_source_mac = str(arp_layer.hwsrc).lower()
        arp_destination_mac = str(arp_layer.hwdst).lower()

    if packet.haslayer(TCP):
        transport_layer = packet[TCP]
        transport_protocol = "TCP"
        source_port = transport_layer.sport
        destination_port = transport_layer.dport
        tcp_flags = str(transport_layer.flags)

    elif packet.haslayer(UDP):
        transport_layer = packet[UDP]
        transport_protocol = "UDP"
        source_port = transport_layer.sport
        destination_port = transport_layer.dport

    if packet.haslayer(DNS):
        dns_layer = packet[DNS]

        protocol = "DNS"
        dns_is_response = bool(dns_layer.qr)
        dns_response_code = int(dns_layer.rcode)
        dns_answer_count = int(dns_layer.ancount or 0)

        question = dns_layer.qd

        if isinstance(question, (list, tuple)):
            question = question[0] if question else None

        if question is not None:
            query_name = question.qname

            if isinstance(query_name, bytes):
                query_name = query_name.decode(
                    "utf-8",
                    errors="replace",
                )

            if isinstance(query_name, str):
                dns_query_name = query_name.rstrip(".").lower()

            dns_query_type = int(question.qtype)

    elif transport_protocol is not None:
        protocol = transport_protocol

    elif (
        packet.haslayer(ICMP)
        or packet.haslayer(ICMPv6Unknown)
        or any(
            layer.__name__.startswith("ICMPv6")
            for layer in packet.layers()
        )
    ):
        protocol = "ICMP"

    elif packet.haslayer(ARP):
        protocol = "ARP"

    else:
        protocol = "OTHER"

    return {
        "timestamp": float(packet.time),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_flags": tcp_flags,
        "transport_protocol": transport_protocol,
        "arp_operation": arp_operation,
        "arp_source_mac": arp_source_mac,
        "arp_destination_mac": arp_destination_mac,
        "dns_query_name": dns_query_name,
        "dns_query_type": dns_query_type,
        "dns_is_response": dns_is_response,
        "dns_response_code": dns_response_code,
        "dns_answer_count": dns_answer_count,
        "protocol": protocol,
        "packet_size": len(packet),
    }
