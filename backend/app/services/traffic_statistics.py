from collections import Counter


def calculate_traffic_statistics(packets):
    if not isinstance(packets, list):
        raise TypeError("Expected a list of packet records.")

    protocol_counts = Counter()
    protocol_bytes = Counter()
    source_counts = Counter()
    destination_counts = Counter()

    total_bytes = 0

    for packet in packets:
        if not isinstance(packet, dict):
            raise TypeError("Each packet must be a dictionary.")

        protocol = packet.get("protocol")
        packet_size = packet.get("packet_size")
        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")

        if not isinstance(protocol, str) or not protocol:
            raise ValueError("Invalid packet protocol.")

        if (
            isinstance(packet_size, bool)
            or not isinstance(packet_size, int)
            or packet_size < 0
        ):
            raise ValueError("Invalid packet size.")

        if source_ip is not None and not isinstance(source_ip, str):
            raise ValueError("Invalid source IP.")

        if destination_ip is not None and not isinstance(destination_ip, str):
            raise ValueError("Invalid destination IP.")

        protocol_counts[protocol] += 1
        protocol_bytes[protocol] += packet_size
        total_bytes += packet_size

        if source_ip:
            source_counts[source_ip] += 1

        if destination_ip:
            destination_counts[destination_ip] += 1

    top_sources = [
        {
            "ip_address": ip,
            "packet_count": count,
        }
        for ip, count in sorted(
            source_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:10]
    ]

    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "protocol_distribution": dict(sorted(protocol_counts.items())),
        "protocol_bytes": dict(sorted(protocol_bytes.items())),
        "unique_source_ips": len(source_counts),
        "unique_destination_ips": len(destination_counts),
        "top_source_ips": top_sources,
    }
