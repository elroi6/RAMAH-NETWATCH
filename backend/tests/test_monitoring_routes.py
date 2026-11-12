import pytest
@pytest.fixture
def client(app):
    return app.test_client()
from app.services import packet_capture


def test_capture_success(app, monkeypatch):
    app.config["NETWATCH_INTERFACE"] = "wlan0"

    def mock_capture(interface, duration, max_packets):
        return {
            "interface": interface,
            "captured_packets": 2,
            "packets": [
                {"protocol": "TCP", "source_ip": "192.168.1.10"},
                {"protocol": "UDP", "source_ip": "192.168.1.20"},
            ],
        }

    monkeypatch.setattr(
        packet_capture,
        "capture_packets",
        mock_capture,
    )

    response = app.test_client().post(
        "/api/monitoring/capture",
        json={"duration": 5, "max_packets": 50},
    )

    assert response.status_code == 200

    data = response.get_json()
    assert data["success"] is True
    assert data["result"]["interface"] == "wlan0"
    assert data["result"]["captured_packets"] == 2


def test_capture_uses_default_options(app, monkeypatch):
    app.config["NETWATCH_INTERFACE"] = "wlan0"
    received = {}

    def mock_capture(interface, duration, max_packets):
        received.update({
            "interface": interface,
            "duration": duration,
            "max_packets": max_packets,
        })
        return {
            "interface": interface,
            "captured_packets": 0,
            "packets": [],
        }

    monkeypatch.setattr(
        packet_capture,
        "capture_packets",
        mock_capture,
    )

    response = app.test_client().post("/api/monitoring/capture")

    assert response.status_code == 200
    assert received == {
        "interface": "wlan0",
        "duration": 10,
        "max_packets": 100,
    }


def test_capture_rejects_invalid_options(app, monkeypatch):
    def mock_capture(*args, **kwargs):
        raise ValueError("Invalid duration")

    monkeypatch.setattr(
        packet_capture,
        "capture_packets",
        mock_capture,
    )

    response = app.test_client().post(
        "/api/monitoring/capture",
        json={"duration": 100},
    )

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_capture_handles_runtime_error(app, monkeypatch):
    def mock_capture(*args, **kwargs):
        raise RuntimeError("Capture failed")

    monkeypatch.setattr(
        packet_capture,
        "capture_packets",
        mock_capture,
    )

    response = app.test_client().post("/api/monitoring/capture")

    assert response.status_code == 503
    assert response.get_json()["success"] is False


def test_capture_requires_interface_configuration(app):
    app.config["NETWATCH_INTERFACE"] = None

    response = app.test_client().post("/api/monitoring/capture")

    assert response.status_code == 500
    assert response.get_json()["success"] is False


def test_capture_rejects_unsupported_fields(app):
    response = app.test_client().post(
        "/api/monitoring/capture",
        json={"interface": "lo"},
    )

    assert response.status_code == 400


def test_capture_rejects_get(app):
    response = app.test_client().get("/api/monitoring/capture")

    assert response.status_code == 405


def test_statistics_success(client, monkeypatch):
    from app.routes import monitoring_routes

    def fake_capture(interface, duration, max_packets):
        return {
            "interface": interface,
            "captured_packets": 2,
            "packets": [
                {
                    "protocol": "TCP",
                    "packet_size": 100,
                    "source_ip": "192.168.1.10",
                    "destination_ip": "192.168.1.20",
                },
                {
                    "protocol": "UDP",
                    "packet_size": 80,
                    "source_ip": "192.168.1.10",
                    "destination_ip": "8.8.8.8",
                },
            ],
        }

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post(
        "/api/monitoring/statistics",
        json={"duration": 5, "max_packets": 50},
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["success"] is True
    assert data["result"]["interface"] == "wlan0"
    assert data["result"]["total_packets"] == 2
    assert data["result"]["total_bytes"] == 180
    assert data["result"]["protocol_distribution"] == {
        "TCP": 1,
        "UDP": 1,
    }


def test_statistics_uses_default_capture_options(client, monkeypatch):
    from app.routes import monitoring_routes

    calls = {}

    def fake_capture(interface, duration, max_packets):
        calls["interface"] = interface
        calls["duration"] = duration
        calls["max_packets"] = max_packets

        return {
            "interface": interface,
            "captured_packets": 0,
            "packets": [],
        }

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post("/api/monitoring/statistics")

    assert response.status_code == 200
    assert calls == {
        "interface": "wlan0",
        "duration": 10,
        "max_packets": 100,
    }


def test_statistics_handles_capture_failure(client, monkeypatch):
    from app.routes import monitoring_routes

    def fake_capture(*args, **kwargs):
        raise RuntimeError("Capture failed")

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post("/api/monitoring/statistics")

    assert response.status_code == 503
    assert response.get_json()["success"] is False


def test_statistics_rejects_invalid_options(client, monkeypatch):
    from app.routes import monitoring_routes

    def fake_capture(*args, **kwargs):
        raise ValueError("Invalid options")

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post(
        "/api/monitoring/statistics",
        json={"duration": 1000},
    )

    assert response.status_code == 400
