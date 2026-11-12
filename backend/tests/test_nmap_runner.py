import json
import subprocess
from types import SimpleNamespace

import pytest

from app.services import nmap_runner


def test_get_interface_network_returns_private_subnet(monkeypatch):
    interface_data = [{
        "addr_info": [{
            "family": "inet",
            "scope": "global",
            "local": "172.20.14.107",
            "prefixlen": 24,
        }]
    }]

    monkeypatch.setattr(
        nmap_runner.shutil,
        "which",
        lambda command: "/usr/sbin/ip",
    )

    monkeypatch.setattr(
        nmap_runner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(interface_data),
            stderr="",
        ),
    )

    network = nmap_runner.get_interface_network("wlan0")

    assert network == "172.20.14.0/24"


def test_get_interface_network_rejects_loopback():
    with pytest.raises(ValueError):
        nmap_runner.get_interface_network("lo")


def test_get_interface_network_rejects_oversized_network(
    monkeypatch,
):
    interface_data = [{
        "addr_info": [{
            "family": "inet",
            "scope": "global",
            "local": "10.0.0.1",
            "prefixlen": 8,
        }]
    }]

    monkeypatch.setattr(
        nmap_runner.shutil,
        "which",
        lambda command: "/usr/sbin/ip",
    )

    monkeypatch.setattr(
        nmap_runner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(interface_data),
            stderr="",
        ),
    )

    with pytest.raises(ValueError, match="too large"):
        nmap_runner.get_interface_network("wlan0")


def test_get_interface_network_handles_missing_interface(
    monkeypatch,
):
    monkeypatch.setattr(
        nmap_runner.shutil,
        "which",
        lambda command: "/usr/sbin/ip",
    )

    monkeypatch.setattr(
        nmap_runner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Interface not found",
        ),
    )

    with pytest.raises(RuntimeError, match="Unable to inspect"):
        nmap_runner.get_interface_network("wlan0")


def test_run_network_discovery_executes_and_syncs_devices(
    monkeypatch,
):
    interface_data = [{
        "addr_info": [{
            "family": "inet",
            "scope": "global",
            "local": "172.20.14.107",
            "prefixlen": 24,
        }]
    }]

    xml_content = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="172.20.14.46" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
        </host>
    </nmaprun>
    """

    monkeypatch.setattr(
        nmap_runner.shutil,
        "which",
        lambda command: (
            "/usr/sbin/ip" if command == "ip"
            else "/usr/bin/nmap"
        ),
    )

    executed_commands = []

    def fake_run(command, **kwargs):
        executed_commands.append(command)

        if command[0] == "/usr/sbin/ip":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(interface_data),
                stderr="",
            )

        xml_path = command[command.index("-oX") + 1]

        with open(xml_path, "w", encoding="utf-8") as file:
            file.write(xml_content)

        return SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        nmap_runner.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        nmap_runner,
        "sync_discovered_devices",
        lambda devices: {
            "created": 1,
            "updated": 0,
            "total": 1,
        },
    )

    result = nmap_runner.run_network_discovery("wlan0")

    assert result["interface"] == "wlan0"
    assert result["network"] == "172.20.14.0/24"
    assert result["discovered"] == 1
    assert result["created"] == 1
    assert result["updated"] == 0

    assert len(executed_commands) == 2
    assert executed_commands[1][0] == "/usr/bin/nmap"
    assert "-sn" in executed_commands[1]
    assert "172.20.14.0/24" in executed_commands[1]
