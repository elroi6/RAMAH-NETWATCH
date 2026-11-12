
import ipaddress
import math
import re
from collections import defaultdict


DEFAULT_TIME_WINDOW = 30

MAC_ADDRESS_PATTERN = re.compile(
    r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
)


def detect_arp_anomalies(
    packets,
    time_window=DEFAULT_TIME_WINDOW,
):
    if not isinstance(packets, list):
        raise TypeError("Expected a list of packet records.")

    if (
        isinstance(time_window, bool)
        or not isinstance(time_window, (int, float))
        or not math.isfinite(time_window)
        or time_window <= 0
    ):
        raise ValueError("Invalid time window.")

    mappings = defaultdict(list)

    for packet in packets:
        if not isinstance(packet, dict):
            raise TypeError("Each packet must be a dictionary.")

        if packet.get("protocol") != "ARP":
            continue

        source_ip = packet.get("source_ip")
        source_mac = packet.get("arp_source_mac")
        timestamp = packet.get("timestamp")

        if not isinstance(source_ip, str) or not source_ip:
            raise ValueError("Invalid ARP source IP address.")

        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError as exc:
            raise ValueError("Invalid ARP source IP address.") from exc

        if (
            not isinstance(source_mac, str)
            or not MAC_ADDRESS_PATTERN.fullmatch(source_mac)
        ):
            raise ValueError("Invalid ARP source MAC address.")

        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not math.isfinite(timestamp)
        ):
            raise ValueError("Invalid ARP packet timestamp.")

        mappings[source_ip].append(
            (float(timestamp), source_mac.lower())
        )

    alerts = []

    for source_ip, observations in mappings.items():
        observations.sort(key=lambda item: item[0])

        left = 0
        mac_counts = defaultdict(int)

        for right, (timestamp, source_mac) in enumerate(observations):
            mac_counts[source_mac] += 1

            while timestamp - observations[left][0] > time_window:
                old_mac = observations[left][1]
                mac_counts[old_mac] -= 1

                if mac_counts[old_mac] == 0:
                    del mac_counts[old_mac]

                left += 1

            if len(mac_counts) > 1:
                alerts.append({
                    "type": "ARP_IP_MAC_CONFLICT",
                    "severity": "HIGH",
                    "ip_address": source_ip,
                    "conflicting_macs": sorted(mac_counts),
                    "time_window_seconds": time_window,
                    "first_seen": observations[left][0],
                    "last_seen": timestamp,
                })

                break

    return alerts
