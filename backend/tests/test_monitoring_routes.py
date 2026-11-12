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
