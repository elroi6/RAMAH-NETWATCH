import subprocess
import xml.etree.ElementTree as ET

import pytest

from app.services.nmap_port_scanner import (
    parse_port_scan_xml,
    scan_device_ports,
    validate_scan_target,
)


def test_parse_port_scan_extracts_open_ports(tmp_path):
    xml_content = """\
    <nmaprun>
        <host>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" product="nginx" version="1.24"/>
                </port>
                <port protocol="tcp" portid="443">
                    <state state="open"/>
                    <service name="https"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """

    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(xml_content)

    result = parse_port_scan_xml(xml_file)

    assert len(result) == 2
    assert result[0]["port"] == 80
    assert result[0]["service"] == "http"
    assert result[0]["product"] == "nginx"
    assert result[0]["version"] == "1.24"


def test_parse_port_scan_ignores_closed_ports(tmp_path):
    xml_content = """\
    <nmaprun>
        <host>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="closed"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """

    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(xml_content)

    result = parse_port_scan_xml(xml_file)

    assert result == []


def test_parse_port_scan_handles_missing_service_information(tmp_path):
    xml_content = """\
    <nmaprun>
        <host>
            <ports>
                <port protocol="tcp" portid="8080">
                    <state state="open"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """

    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(xml_content)

    result = parse_port_scan_xml(xml_file)

    assert len(result) == 1
    assert result[0]["port"] == 8080
    assert result[0]["service"] is None
    assert result[0]["product"] is None
    assert result[0]["version"] is None


def test_parse_port_scan_rejects_invalid_xml(tmp_path):
    xml_file = tmp_path / "invalid.xml"
    xml_file.write_text("<nmaprun><host>")

    with pytest.raises(ET.ParseError):
        parse_port_scan_xml(xml_file)
from app.services.nmap_port_scanner import validate_scan_target


def test_validate_scan_target_accepts_private_ipv4():
    assert validate_scan_target("192.168.1.20") == "192.168.1.20"


@pytest.mark.parametrize(
    "target",
    [
        "not-an-ip",
        "2001:db8::1",
        "8.8.8.8",
        "127.0.0.1",
        "169.254.1.1",
    ],
)
def test_validate_scan_target_rejects_unsafe_addresses(target):
    with pytest.raises(ValueError):
        validate_scan_target(target)


def test_scan_device_ports_handles_nmap_timeout(monkeypatch):

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="nmap",
            timeout=120,
        )

    monkeypatch.setattr(
        "app.services.nmap_port_scanner.subprocess.run",
        mock_run,
    )

    with pytest.raises(RuntimeError, match="timed out"):
        scan_device_ports("192.168.1.20")


def test_scan_device_ports_handles_nmap_failure(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        "app.services.nmap_port_scanner.shutil.which",
        lambda name: "/usr/bin/nmap",
    )

    monkeypatch.setattr(
        "app.services.nmap_port_scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stderr="Nmap failed",
        ),
    )

    with pytest.raises(RuntimeError, match="Nmap port scan failed"):
        scan_device_ports("192.168.1.20")


def test_scan_device_ports_handles_invalid_xml(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        "app.services.nmap_port_scanner.shutil.which",
        lambda name: "/usr/bin/nmap",
    )

    def mock_run(command, **kwargs):
        output_index = command.index("-oX") + 1
        xml_path = command[output_index]

        with open(xml_path, "w", encoding="utf-8") as file:
            file.write("<nmaprun><host>")

        return SimpleNamespace(
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr(
        "app.services.nmap_port_scanner.subprocess.run",
        mock_run,
    )

    with pytest.raises(RuntimeError, match="Invalid Nmap scan output"):
        scan_device_ports("192.168.1.20")
