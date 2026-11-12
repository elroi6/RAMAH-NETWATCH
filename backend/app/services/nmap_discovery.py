import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    devices = []

    for host in root.findall("host"):
        status_element = host.find("status")

        if status_element is None:
            continue

        if status_element.get("state") != "up":
            continue

        ip_address = None
        mac_address = None
        hostname = None

        for address in host.findall("address"):
            address_type = address.get("addrtype")

            if address_type == "ipv4":
                ip_address = address.get("addr")

            elif address_type == "mac":
                mac_address = address.get("addr")

        hostname_element = host.find("./hostnames/hostname")

        if hostname_element is not None:
            hostname = hostname_element.get("name")

        if not ip_address:
            continue

        devices.append({
            "ip_address": ip_address,
            "mac_address": mac_address,
            "hostname": hostname,
            "operating_system": None,
            "status": "online",
            "open_ports": [],
        })

    return devices
