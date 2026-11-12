
import math
from collections import defaultdict


DEFAULT_TIME_WINDOW = 10
DEFAULT_PORT_THRESHOLD = 10


def detect_port_scans(
    packets,
    time_window=DEFAULT_TIME_WINDOW,
    port_threshold=DEFAULT_PORT_THRESHOLD,
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

    if (
        isinstance(port_threshold, bool)
        or not isinstance(port_threshold, int)
        or port_threshold < 2
    ):
        raise ValueError("Invalid port threshold.")

    groups = defaultdict(list)

    for packet in packets:
        if not isinstance(packet, dict):
            raise TypeError("Each packet must be a dictionary.")

        if packet.get("protocol") != "TCP":
            continue

        flags = packet.get("tcp_flags", "")
        if not isinstance(flags, str):
            raise ValueError("Invalid TCP flags.")

        # Only count initial SYN packets, not SYN-ACK responses.
        if "S" not in flags or "A" in flags:
            continue

        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")
        destination_port = packet.get("destination_port")
        timestamp = packet.get("timestamp")

        if (
            not isinstance(source_ip, str)
            or not source_ip
            or not isinstance(destination_ip, str)
            or not destination_ip
        ):
            raise ValueError("Invalid packet IP address.")

        if (
            isinstance(destination_port, bool)
            or not isinstance(destination_port, int)
            or not 1 <= destination_port <= 65535
        ):
            raise ValueError("Invalid destination port.")

        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not math.isfinite(timestamp)
        ):
            raise ValueError("Invalid packet timestamp.")

        groups[(source_ip, destination_ip)].append(
            (float(timestamp), destination_port)
        )

    alerts = []

    for (source_ip, destination_ip), attempts in groups.items():
        attempts.sort(key=lambda item: item[0])

        left = 0
        ports = defaultdict(int)

        for right, (timestamp, destination_port) in enumerate(attempts):
            ports[destination_port] += 1

            while timestamp - attempts[left][0] > time_window:
                old_port = attempts[left][1]
                ports[old_port] -= 1

                if ports[old_port] == 0:
                    del ports[old_port]

                left += 1

            if len(ports) >= port_threshold:
                alerts.append({
                    "type": "POSSIBLE_PORT_SCAN",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "unique_destination_ports": len(ports),
                    "syn_packets": right - left + 1,
                    "time_window_seconds": time_window,
                    "first_seen": attempts[left][0],
                    "last_seen": timestamp,
                })

                break

    return alerts
