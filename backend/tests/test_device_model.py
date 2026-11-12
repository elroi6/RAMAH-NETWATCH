from app import db
from app.models import Device


def test_device_creation(app):
    with app.app_context():
        device = Device(
            ip_address="192.168.1.10",
            mac_address="AA:BB:CC:DD:EE:FF",
            hostname="test-device",
            operating_system="Linux",
            status="online",
            open_ports=[22, 80, 443],
        )

        db.session.add(device)
        db.session.commit()

        saved_device = db.session.get(Device, device.id)

        assert saved_device is not None
        assert saved_device.ip_address == "192.168.1.10"
        assert saved_device.mac_address == "AA:BB:CC:DD:EE:FF"
        assert saved_device.hostname == "test-device"
        assert saved_device.open_ports == [22, 80, 443]
        assert saved_device.status == "online"


def test_device_to_dict(app):
    with app.app_context():
        device = Device(
            ip_address="192.168.1.20",
            hostname="laptop",
            status="online",
        )

        db.session.add(device)
        db.session.commit()

        data = device.to_dict()

        assert data["ip_address"] == "192.168.1.20"
        assert data["hostname"] == "laptop"
        assert data["status"] == "online"
        assert isinstance(data["first_seen"], str)
        assert isinstance(data["last_seen"], str)
