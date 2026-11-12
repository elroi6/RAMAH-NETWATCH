
import ipaddress
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from pathlib import Path


PORT_SCAN_TIMEOUT = 120
MAX_PORTS = 1000


def validate_scan_target(ip_address):
    try:
        target = ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise ValueError("Invalid IP address.") from exc

    if target.version != 4:
        raise ValueError("Only IPv4 addresses are supported.")

    if not target.is_private or target.is_loopback or target.is_link_local:
        raise ValueError("Only private network targets are supported.")

    return str(target)


def scan_device_ports(ip_address, ports="1-1000"):
    target = validate_scan_target(ip_address)

    if ports != "1-1000":
        raise ValueError("Unsupported port range.")

    nmap_binary = shutil.which("nmap")

    if not nmap_binary:
        raise RuntimeError("Nmap is not installed.")

    with tempfile.TemporaryDirectory(
        prefix="ramah-netwatch-"
    ) as temporary_directory:

        xml_path = Path(temporary_directory) / "ports.xml"

        try:
            result = subprocess.run(
                [
                    nmap_binary,
                    "-sT",
                    "-sV",
                    "--version-light",
                    "-n",
                    "-p",
                    ports,
                    "-oX",
                    str(xml_path),
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=PORT_SCAN_TIMEOUT,
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Nmap port scan timed out.") from exc

        if result.returncode != 0:
            raise RuntimeError("Nmap port scan failed.")

        try:
            return parse_port_scan_xml(xml_path)
        except (ET.ParseError, OSError, ValueError) as exc:
            raise RuntimeError("Invalid Nmap scan output.") from exc


def parse_port_scan_xml(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    ports = []

    for port in root.findall(".//port"):
        state_element = port.find("state")

        if state_element is None:
            continue

        if state_element.get("state") != "open":
            continue

        service_element = port.find("service")

        service = {
            "port": int(port.get("portid")),
            "protocol": port.get("protocol"),
            "state": "open",
            "service": None,
            "product": None,
            "version": None,
        }

        if service_element is not None:
            service["service"] = service_element.get("name")
            service["product"] = service_element.get("product")
            service["version"] = service_element.get("version")

        ports.append(service)

    return ports
