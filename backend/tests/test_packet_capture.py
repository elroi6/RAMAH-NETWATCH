import subprocess
from types import SimpleNamespace

import pytest

from scapy.layers.inet import IP, TCP

from app.services.packet_capture import (
    capture_packets,
    validate_capture_options,
)


def test_validate_capture_options_accepts_valid_values():
    assert validate_capture_options("wlan0", 10, 100) == "wlan0"


@pytest.mark.parametrize(
    "interface",
    ["", "lo;whoami", "interface name", "../wlan0", "a" * 16],
)
def test_validate_capture_options_rejects_invalid_interfaces(interface):
    with pytest.raises(ValueError, match="interface"):
        validate_capture_options(interface, 10, 100)


@pytest.mark.parametrize("duration", [0, 61, -1, True, "10"])
def test_validate_capture_options_rejects_invalid_duration(duration):
    with pytest.raises(ValueError, match="duration"):
        validate_capture_options("wlan0", duration, 100)


@pytest.mark.parametrize("max_packets", [0, 1001, -1, True, "100"])
def test_validate_capture_options_rejects_invalid_packet_limit(max_packets):
    with pytest.raises(ValueError, match="packet count"):
        validate_capture_options("wlan0", 10, max_packets)


def test_capture_packets_analyzes_captured_packets(monkeypatch):
    packet = IP(
        src="192.168.1.10",
        dst="192.168.1.20"
    ) / TCP(sport=12345, dport=443)

    class MockReader:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def __iter__(self):
            return iter([packet])

    def mock_run(command, **kwargs):
        capture_path = command[command.index("-w") + 1]
        open(capture_path, "wb").close()

        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(
        "app.services.packet_capture.shutil.which",
        lambda name: "/usr/bin/dumpcap",
    )

    monkeypatch.setattr(
        "app.services.packet_capture.subprocess.run",
        mock_run,
    )

    monkeypatch.setattr(
        "app.services.packet_capture.PcapReader",
        MockReader,
    )

    result = capture_packets("wlan0", 5, 50)

    assert result["interface"] == "wlan0"
    assert result["captured_packets"] == 1
    assert result["packets"][0]["protocol"] == "TCP"
    assert result["packets"][0]["destination_port"] == 443


def test_capture_packets_handles_missing_dumpcap(monkeypatch):
    monkeypatch.setattr(
        "app.services.packet_capture.shutil.which",
        lambda name: None,
    )

    with pytest.raises(RuntimeError, match="not installed"):
        capture_packets("wlan0")


def test_capture_packets_handles_timeout(monkeypatch):
    monkeypatch.setattr(
        "app.services.packet_capture.shutil.which",
        lambda name: "/usr/bin/dumpcap",
    )

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired("dumpcap", 20)

    monkeypatch.setattr(
        "app.services.packet_capture.subprocess.run",
        mock_run,
    )

    with pytest.raises(RuntimeError, match="timed out"):
        capture_packets("wlan0", 10, 100)


def test_capture_packets_handles_capture_failure(monkeypatch):
    monkeypatch.setattr(
        "app.services.packet_capture.shutil.which",
        lambda name: "/usr/bin/dumpcap",
    )

    monkeypatch.setattr(
        "app.services.packet_capture.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stderr="Capture failed",
        ),
    )

    with pytest.raises(RuntimeError, match="capture failed"):
        capture_packets("wlan0")


def test_capture_packets_rejects_missing_output(monkeypatch):
    monkeypatch.setattr(
        "app.services.packet_capture.shutil.which",
        lambda name: "/usr/bin/dumpcap",
    )

    monkeypatch.setattr(
        "app.services.packet_capture.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError, match="output was not created"):
        capture_packets("wlan0")
