
import pytest

from app import db
from app.models import Device
from app.services.unknown_device_detector import detect_unknown_devices


NETWORK = "192.168.1.0/24"

KNOWN_IP = "192.168.1.10"
KNOWN_MAC = "00:11:22:33:44:55"

UNKNOWN_IP = "192.168.1.50"
UNKNOWN_MAC = "AA:BB:CC:DD:EE:FF"


def make_packet(source_ip, source_mac):
    return {
        "source_ip": source_ip,
        "source_mac": source_mac,
        "protocol": "TCP",
    }


def add_device(ip_address, mac_address):
    device = Device(
        ip_address=ip_address,
        mac_address=mac_address,
        status="online",
    )

    db.session.add(device)
    db.session.commit()

    return device


def test_detects_unknown_device(app):
    with app.app_context():
        alerts = detect_unknown_devices([
            make_packet(UNKNOWN_IP, UNKNOWN_MAC)
        ], NETWORK)

        assert len(alerts) == 1
        assert alerts[0]["type"] == "UNKNOWN_DEVICE"
        assert alerts[0]["severity"] == "MEDIUM"
        assert alerts[0]["source_ip"] == UNKNOWN_IP
        assert alerts[0]["source_mac"] == UNKNOWN_MAC.lower()


def test_ignores_known_device(app):
    with app.app_context():
        add_device(KNOWN_IP, KNOWN_MAC)

        alerts = detect_unknown_devices([
            make_packet(KNOWN_IP, KNOWN_MAC)
        ], NETWORK)

        assert alerts == []


def test_detects_changed_mac_for_known_ip(app):
    with app.app_context():
        add_device(KNOWN_IP, KNOWN_MAC)

        alerts = detect_unknown_devices([
            make_packet(KNOWN_IP, UNKNOWN_MAC)
        ], NETWORK)

        assert len(alerts) == 1
        assert alerts[0]["type"] == "DEVICE_MAC_CHANGED"
        assert alerts[0]["source_ip"] == KNOWN_IP


def test_ignores_known_device_without_recorded_mac(app):
    with app.app_context():
        add_device(KNOWN_IP, None)

        alerts = detect_unknown_devices([
            make_packet(KNOWN_IP, UNKNOWN_MAC)
        ], NETWORK)

        assert alerts == []


def test_ignores_external_ip_addresses(app):
    with app.app_context():
        alerts = detect_unknown_devices([
            make_packet("8.8.8.8", UNKNOWN_MAC)
        ], NETWORK)

        assert alerts == []


def test_ignores_packets_without_mac_addresses(app):
    with app.app_context():
        alerts = detect_unknown_devices([
            {
                "source_ip": UNKNOWN_IP,
                "source_mac": None,
            }
        ], NETWORK)

        assert alerts == []


def test_deduplicates_repeated_unknown_devices(app):
    with app.app_context():
        packets = [
            make_packet(UNKNOWN_IP, UNKNOWN_MAC),
            make_packet(UNKNOWN_IP, UNKNOWN_MAC),
            make_packet(UNKNOWN_IP, UNKNOWN_MAC),
        ]

        alerts = detect_unknown_devices(packets, NETWORK)

        assert len(alerts) == 1


def test_ignores_ipv6_source_addresses(app):
    with app.app_context():
        alerts = detect_unknown_devices([
            make_packet("2001:db8::1", UNKNOWN_MAC)
        ], NETWORK)

        assert alerts == []


def test_rejects_invalid_source_ip(app):
    with app.app_context():
        with pytest.raises(ValueError):
            detect_unknown_devices([
                make_packet("invalid-ip", UNKNOWN_MAC)
            ], NETWORK)


@pytest.mark.parametrize(
    "source_mac",
    ["invalid-mac", "","00:11:22:33:44"],
)
def test_rejects_invalid_source_mac(app, source_mac):
    with app.app_context():
        with pytest.raises(ValueError):
            detect_unknown_devices([
                make_packet(UNKNOWN_IP, source_mac)
            ], NETWORK)


@pytest.mark.parametrize(
    "network",
    [
        "invalid-network",
        "192.168.1.1/24",
        "8.8.8.0/24",
        "2001:db8::/64",
        None,
    ],
)
def test_rejects_invalid_network(app, network):
    with app.app_context():
        with pytest.raises(ValueError):
            detect_unknown_devices([], network)


def test_rejects_invalid_packet_collection(app):
    with app.app_context():
        with pytest.raises(TypeError):
            detect_unknown_devices("not a list", NETWORK)


def test_rejects_non_dictionary_packet(app):
    with app.app_context():
        with pytest.raises(TypeError):
            detect_unknown_devices(["not a dictionary"], NETWORK)


def test_returns_empty_list_for_no_packets(app):
    with app.app_context():
        assert detect_unknown_devices([], NETWORK) == []
