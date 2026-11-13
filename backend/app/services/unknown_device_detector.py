
import ipaddress
import re

from collections import defaultdict

from app.models.device import Device


MAC_ADDRESS_PATTERN = re.compile(
    r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
)


def detect_unknown_devices(packets, network):
    if not isinstance(packets, list):
        raise TypeError("Expected a list of packet records.")

    try:
        monitored_network = ipaddress.ip_network(
            network,
            strict=True,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid monitored network.") from exc

    if (
        not isinstance(monitored_network, ipaddress.IPv4Network)
        or not monitored_network.is_private
    ):
        raise ValueError("Only private IPv4 networks are supported.")

    known_devices = Device.query.all()

    known_ips = set()
    known_macs_by_ip = defaultdict(set)

    for device in known_devices:
        try:
            device_ip = ipaddress.ip_address(device.ip_address)
        except ValueError:
            continue

        if (
            not isinstance(device_ip, ipaddress.IPv4Address)
            or device_ip not in monitored_network
        ):
            continue

        normalized_ip = str(device_ip)
        known_ips.add(normalized_ip)

        if (
            isinstance(device.mac_address, str)
            and MAC_ADDRESS_PATTERN.fullmatch(device.mac_address)
        ):
            known_macs_by_ip[normalized_ip].add(
                device.mac_address.lower()
            )

    unknown_devices = {}

    for packet in packets:
        if not isinstance(packet, dict):
            raise TypeError("Each packet must be a dictionary.")

        source_ip = packet.get("source_ip")
        source_mac = packet.get("source_mac")

        if source_ip is None or source_mac is None:
            continue

        if not isinstance(source_ip, str):
            raise ValueError("Invalid source IP address.")

        try:
            parsed_ip = ipaddress.ip_address(source_ip)
        except ValueError as exc:
            raise ValueError("Invalid source IP address.") from exc

        if not isinstance(parsed_ip, ipaddress.IPv4Address):
            continue

        if parsed_ip not in monitored_network:
            continue

        if (
            not isinstance(source_mac, str)
            or not MAC_ADDRESS_PATTERN.fullmatch(source_mac)
        ):
            raise ValueError("Invalid source MAC address.")

        normalized_ip = str(parsed_ip)
        normalized_mac = source_mac.lower()

        if normalized_ip in known_ips:
            known_macs = known_macs_by_ip[normalized_ip]

            if not known_macs:
                continue

            if normalized_mac in known_macs:
                continue

            alert_type = "DEVICE_MAC_CHANGED"
        else:
            alert_type = "UNKNOWN_DEVICE"

        device_key = (normalized_ip, normalized_mac)

        if device_key not in unknown_devices:
            unknown_devices[device_key] = {
                "type": alert_type,
                "severity": "MEDIUM",
                "source_ip": normalized_ip,
                "source_mac": normalized_mac,
            }

    return sorted(
        unknown_devices.values(),
        key=lambda alert: (
            alert["source_ip"],
            alert["source_mac"],
        ),
    )
