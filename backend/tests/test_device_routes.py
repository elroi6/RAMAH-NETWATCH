from app import db
from app.models import Device


def test_get_devices(app):
    with app.app_context():
        device = Device(
            ip_address="192.168.1.10",
            hostname="test-laptop",
            status="online",
        )

        db.session.add(device)
        db.session.commit()

    client = app.test_client()
    response = client.get("/api/devices")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["count"] == 1
    assert data["devices"][0]["hostname"] == "test-laptop"


def test_get_single_device(app):
    with app.app_context():
        device = Device(
            ip_address="192.168.1.20",
            hostname="test-server",
            status="online",
        )

        db.session.add(device)
        db.session.commit()
        device_id = device.id

    client = app.test_client()
    response = client.get(f"/api/devices/{device_id}")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["device"]["ip_address"] == "192.168.1.20"


def test_get_nonexistent_device(app):
    client = app.test_client()

    response = client.get("/api/devices/99999")

    assert response.status_code == 404

    data = response.get_json()

    assert data["success"] is False
    assert data["message"] == "Device not found"
def test_enumerate_device_success(app, monkeypatch):
    with app.app_context():
        device = Device(
            ip_address="192.168.1.30",
            hostname="test-device",
            status="online",
        )

        db.session.add(device)
        db.session.commit()
        device_id = device.id

    expected_result = {
        "ip_address": "192.168.1.30",
        "open_ports": [
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": None,
                "version": None,
            }
        ],
        "status": "online",
    }

    monkeypatch.setattr(
        "app.routes.device_routes.enumerate_device",
        lambda ip_address: expected_result,
    )

    client = app.test_client()
    response = client.post(
        f"/api/devices/{device_id}/enumerate"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["message"] == "Device enumeration completed."
    assert data["device"] == expected_result


def test_enumerate_nonexistent_device(app):
    client = app.test_client()

    response = client.post(
        "/api/devices/99999/enumerate"
    )

    assert response.status_code == 404

    data = response.get_json()

    assert data["success"] is False
    assert data["message"] == "Device not found."


def test_enumerate_device_invalid_target(app, monkeypatch):
    with app.app_context():
        device = Device(
            ip_address="192.168.1.40",
            status="online",
        )

        db.session.add(device)
        db.session.commit()
        device_id = device.id

    def raise_invalid_target(ip_address):
        raise ValueError("Invalid IP address.")

    monkeypatch.setattr(
        "app.routes.device_routes.enumerate_device",
        raise_invalid_target,
    )

    client = app.test_client()
    response = client.post(
        f"/api/devices/{device_id}/enumerate"
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["success"] is False
    assert data["message"] == "Invalid enumeration target."


def test_enumerate_device_service_failure(app, monkeypatch):
    with app.app_context():
        device = Device(
            ip_address="192.168.1.50",
            status="online",
        )

        db.session.add(device)
        db.session.commit()
        device_id = device.id

    def raise_service_error(ip_address):
        raise RuntimeError("Nmap failed.")

    monkeypatch.setattr(
        "app.routes.device_routes.enumerate_device",
        raise_service_error,
    )

    client = app.test_client()
    response = client.post(
        f"/api/devices/{device_id}/enumerate"
    )

    assert response.status_code == 503

    data = response.get_json()

    assert data["success"] is False
    assert data["message"] == (
        "Device enumeration could not be completed."
    )
