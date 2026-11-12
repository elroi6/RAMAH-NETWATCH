import ipaddress

from flask import current_app

from app.models import Device
from app.services.device_inventory import sync_device_ports
from app.services.nmap_port_scanner import scan_device_ports
from app.services.nmap_runner import get_interface_network


def enumerate_device(ip_address):
    try:
        target_ip = ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise ValueError("Invalid IP address.") from exc

    if target_ip.version != 4:
        raise ValueError("Only IPv4 addresses are supported.")

    interface = current_app.config.get("NETWATCH_INTERFACE")

    if not interface:
        raise RuntimeError("Network interface is not configured.")

    network = ipaddress.ip_network(
        get_interface_network(interface)
    )

    if (
        target_ip not in network
        or target_ip == network.network_address
        or target_ip == network.broadcast_address
    ):
        raise ValueError("Target is outside the configured network.")

    device = Device.query.filter_by(
        ip_address=str(target_ip)
    ).first()

    if device is None:
        raise ValueError("Device not found in inventory.")

    discovered_ports = scan_device_ports(str(target_ip))

    updated_device = sync_device_ports(
        str(target_ip),
        discovered_ports,
    )

    return {
        "ip_address": updated_device["ip_address"],
        "open_ports": updated_device["open_ports"],
        "status": updated_device["status"],
    }
