from datetime import datetime, timezone

from app import db
from app.models import Device
from app.services.device_inventory import sync_discovered_devices


def test_sync_creates_new_devices(app):
    with app.app_context():
        discovered = [
            {
                "ip_address": "192.168.1.10",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "hostname": "test-laptop",
                "operating_system": None,
                "status": "online",
                "open_ports": [],
            }
        ]

        result = sync_discovered_devices(discovered)

        device = Device.query.filter_by(
            ip_address="192.168.1.10"
        ).first()

        assert result == {
            "created": 1,
            "updated": 0,
            "total": 1,
        }

        assert device is not None
        assert device.hostname == "test-laptop"
        assert device.status == "online"


def test_sync_updates_existing_device(app):
    with app.app_context():
        device = Device(
            ip_address="192.168.1.20",
            hostname="old-name",
            status="online",
        )

        db.session.add(device)
        db.session.commit()

        original_first_seen = device.first_seen

        discovered = [
            {
                "ip_address": "192.168.1.20",
                "mac_address": "AA:BB:CC:DD:EE:20",
                "hostname": "updated-name",
                "operating_system": None,
                "status": "online",
                "open_ports": [],
            }
        ]

        result = sync_discovered_devices(discovered)

        db.session.refresh(device)

        assert result["created"] == 0
        assert result["updated"] == 1
        assert device.hostname == "updated-name"
        assert device.mac_address == "AA:BB:CC:DD:EE:20"
        assert device.first_seen == original_first_seen
        assert device.last_seen is not None


def test_sync_preserves_existing_information(app):
    with app.app_context():
        device = Device(
            ip_address="192.168.1.30",
            hostname="existing-device",
            operating_system="Linux",
            status="online",
            open_ports=[22, 80, 443],
        )

        db.session.add(device)
        db.session.commit()

        discovered = [
            {
                "ip_address": "192.168.1.30",
                "mac_address": None,
                "hostname": None,
                "operating_system": None,
                "status": "online",
                "open_ports": [],
            }
        ]

        sync_discovered_devices(discovered)

        db.session.refresh(device)

        assert device.hostname == "existing-device"
        assert device.operating_system == "Linux"
        assert device.open_ports == [22, 80, 443]


def test_sync_handles_multiple_devices(app):
    with app.app_context():
        discovered = [
            {
                "ip_address": "192.168.1.40",
                "status": "online",
                "open_ports": [],
            },
            {
                "ip_address": "192.168.1.41",
                "status": "online",
                "open_ports": [],
            },
        ]

        result = sync_discovered_devices(discovered)

        assert result["created"] == 2
        assert result["updated"] == 0
        assert Device.query.count() == 2
from app.services.device_inventory import sync_device_ports


def test_sync_device_ports_updates_existing_device(app):
    from app import db
    from app.models import Device

    with app.app_context():
        device = Device(
            ip_address="192.168.1.20",
            status="online",
            open_ports=[],
        )

        db.session.add(device)
        db.session.commit()

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

        result = sync_device_ports(
            "192.168.1.20",
            discovered_ports,
        )

        assert result["open_ports"] == discovered_ports
        assert result["ip_address"] == "192.168.1.20"


def test_sync_device_ports_rejects_unknown_device(app):
    with app.app_context():
        import pytest

        with pytest.raises(ValueError, match="Device not found"):
            sync_device_ports(
                "192.168.1.99",
                [],
            )


def test_sync_device_ports_allows_empty_results(app):
    from app import db
    from app.models import Device

    with app.app_context():
        device = Device(
            ip_address="192.168.1.30",
            status="online",
            open_ports=[
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                }
            ],
        )

        db.session.add(device)
        db.session.commit()

        result = sync_device_ports(
            "192.168.1.30",
            [],
        )

        assert result["open_ports"] == []
