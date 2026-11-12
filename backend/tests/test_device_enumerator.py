import pytest

from app import db
from app.models import Device
from app.services.device_enumerator import enumerate_device


def create_test_device():
    device = Device(
        ip_address="192.168.1.20",
        status="online",
        open_ports=[],
    )
    db.session.add(device)
    db.session.commit()


def mock_network(monkeypatch):
    monkeypatch.setattr(
        "app.services.device_enumerator.get_interface_network",
        lambda interface: "192.168.1.0/24",
    )


def test_enumerate_device_scans_and_updates_inventory(app, monkeypatch):
    with app.app_context():
        create_test_device()
        mock_network(monkeypatch)

        discovered_ports = [
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "nginx",
                "version": "1.24",
            }
        ]

        monkeypatch.setattr(
            "app.services.device_enumerator.scan_device_ports",
            lambda ip: discovered_ports,
        )

        result = enumerate_device("192.168.1.20")

        assert result["ip_address"] == "192.168.1.20"
        assert result["open_ports"] == discovered_ports
        assert result["status"] == "online"


def test_enumerate_device_rejects_unknown_device(app, monkeypatch):
    with app.app_context():
        mock_network(monkeypatch)

        def unexpected_scan(ip):
            pytest.fail("Nmap should not run for an unknown device.")

        monkeypatch.setattr(
            "app.services.device_enumerator.scan_device_ports",
            unexpected_scan,
        )

        with pytest.raises(ValueError, match="Device not found"):
            enumerate_device("192.168.1.99")


def test_enumerate_device_rejects_invalid_ip(app, monkeypatch):
    with app.app_context():
        with pytest.raises(ValueError, match="Invalid IP"):
            enumerate_device("not-an-ip")


@pytest.mark.parametrize(
    "target",
    [
        "192.168.2.20",
        "192.168.1.0",
        "192.168.1.255",
        "2001:db8::1",
    ],
)
def test_enumerate_device_rejects_out_of_scope_targets(
    app, monkeypatch, target
):
    with app.app_context():
        mock_network(monkeypatch)

        def unexpected_scan(ip):
            pytest.fail("Nmap should not run for an out-of-scope target.")

        monkeypatch.setattr(
            "app.services.device_enumerator.scan_device_ports",
            unexpected_scan,
        )

        with pytest.raises(ValueError):
            enumerate_device(target)


def test_enumerate_device_propagates_scanner_error(app, monkeypatch):
    with app.app_context():
        create_test_device()
        mock_network(monkeypatch)

        def failed_scan(ip):
            raise RuntimeError("Nmap scan failed.")

        monkeypatch.setattr(
            "app.services.device_enumerator.scan_device_ports",
            failed_scan,
        )

        with pytest.raises(RuntimeError, match="Nmap scan failed"):
            enumerate_device("192.168.1.20")
