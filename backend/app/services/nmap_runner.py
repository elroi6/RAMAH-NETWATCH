import ipaddress
import json
import shutil
import subprocess
import tempfile

from pathlib import Path

from app.services.device_inventory import sync_discovered_devices
from app.services.nmap_discovery import parse_nmap_xml


MAX_NETWORK_ADDRESSES = 256
SCAN_TIMEOUT = 120


def get_interface_network(interface):
    if not interface or interface == "lo":
        raise ValueError("Invalid network interface.")

    ip_binary = shutil.which("ip")

    if not ip_binary:
        raise RuntimeError("The ip command is not installed.")

    result = subprocess.run(
        [ip_binary, "-j", "-4", "addr", "show", "dev", interface],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError("Unable to inspect network interface.")

    try:
        interfaces = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Invalid interface information.") from exc

    for item in interfaces:
        for address in item.get("addr_info", []):
            if address.get("family") != "inet":
                continue

            if address.get("scope") != "global":
                continue

            network_interface = ipaddress.ip_interface(
                f'{address["local"]}/{address["prefixlen"]}'
            )

            network = network_interface.network

            if not network.is_private:
                raise ValueError("Only private IPv4 networks are supported.")

            if network.num_addresses > MAX_NETWORK_ADDRESSES:
                raise ValueError("Network is too large to scan.")

            return str(network)

    raise ValueError("No suitable IPv4 network found on this interface.")


def run_network_discovery(interface):
    target_network = get_interface_network(interface)

    nmap_binary = shutil.which("nmap")

    if not nmap_binary:
        raise RuntimeError("Nmap is not installed.")

    with tempfile.TemporaryDirectory(
        prefix="ramah-netwatch-"
    ) as temporary_directory:

        xml_path = Path(temporary_directory) / "discovery.xml"

        result = subprocess.run(
            [
                nmap_binary,
                "-sn",
                "-n",
                "-oX",
                str(xml_path),
                target_network,
            ],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Nmap discovery failed: {result.stderr[:500]}"
            )

        discovered_devices = parse_nmap_xml(xml_path)

        synchronization = sync_discovered_devices(
            discovered_devices
        )

    return {
        "interface": interface,
        "network": target_network,
        "discovered": len(discovered_devices),
        "created": synchronization["created"],
        "updated": synchronization["updated"],
        "total": synchronization["total"],
    }
