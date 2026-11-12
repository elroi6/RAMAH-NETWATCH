import pytest

from app.services.nmap_discovery import parse_nmap_xml


def test_parse_nmap_xml_extracts_online_devices(tmp_path):
    xml_content = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
        </host>
    </nmaprun>
    """

    xml_file = tmp_path / "discovery.xml"
    xml_file.write_text(xml_content)

    devices = parse_nmap_xml(str(xml_file))

    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.10"
    assert devices[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert devices[0]["status"] == "online"


def test_parse_nmap_xml_extracts_hostname(tmp_path):
    xml_content = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.20" addrtype="ipv4"/>
            <hostnames>
                <hostname name="test-device" type="PTR"/>
            </hostnames>
        </host>
    </nmaprun>
    """

    xml_file = tmp_path / "discovery.xml"
    xml_file.write_text(xml_content)

    devices = parse_nmap_xml(str(xml_file))

    assert len(devices) == 1
    assert devices[0]["hostname"] == "test-device"


def test_parse_nmap_xml_ignores_down_hosts(tmp_path):
    xml_content = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="down"/>
            <address addr="192.168.1.30" addrtype="ipv4"/>
        </host>
    </nmaprun>
    """

    xml_file = tmp_path / "discovery.xml"
    xml_file.write_text(xml_content)

    devices = parse_nmap_xml(str(xml_file))

    assert devices == []


def test_parse_nmap_xml_handles_missing_mac(tmp_path):
    xml_content = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.40" addrtype="ipv4"/>
        </host>
    </nmaprun>
    """

    xml_file = tmp_path / "discovery.xml"
    xml_file.write_text(xml_content)

    devices = parse_nmap_xml(str(xml_file))

    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.40"
    assert devices[0]["mac_address"] is None


def test_parse_nmap_xml_ignores_hosts_without_ipv4(tmp_path):
    xml_content = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
        </host>
    </nmaprun>
    """

    xml_file = tmp_path / "discovery.xml"
    xml_file.write_text(xml_content)

    devices = parse_nmap_xml(str(xml_file))

    assert devices == []


def test_parse_nmap_xml_rejects_invalid_xml(tmp_path):
    xml_file = tmp_path / "invalid.xml"
    xml_file.write_text("<nmaprun><host>")

    with pytest.raises(Exception):
        parse_nmap_xml(str(xml_file))
