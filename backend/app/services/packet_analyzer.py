
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

    arp_operation = None
    arp_source_mac = None
    arp_destination_mac = None

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
        protocol = "TCP"
        source_port = transport_layer.sport
        destination_port = transport_layer.dport
        tcp_flags = str(transport_layer.flags)

    elif packet.haslayer(UDP):
        transport_layer = packet[UDP]
        protocol = "UDP"
        source_port = transport_layer.sport
        destination_port = transport_layer.dport

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

    elif packet.haslayer(IP) or packet.haslayer(IPv6):
        protocol = "OTHER"

    else:
        protocol = "OTHER"

    return {
        "timestamp": float(packet.time),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_flags": tcp_flags,
        "arp_operation": arp_operation,
        "arp_source_mac": arp_source_mac,
        "arp_destination_mac": arp_destination_mac,
        "protocol": protocol,
        "packet_size": len(packet),
    }
