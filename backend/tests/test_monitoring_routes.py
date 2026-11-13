import pytest

from app.services import packet_capture


@pytest.fixture
def client(app):
    return app.test_client()


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


def test_detection_finds_port_scan(client, monkeypatch):
    from app.routes import monitoring_routes

    packets = [
        {
            "protocol": "TCP",
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": port,
            "timestamp": 1000 + index * 0.5,
            "tcp_flags": "S",
        }
        for index, port in enumerate(range(20, 30))
    ]

    def fake_capture(interface, duration, max_packets):
        return {
            "interface": interface,
            "captured_packets": len(packets),
            "packets": packets,
        }

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post("/api/monitoring/detect")

    data = response.get_json()

    assert response.status_code == 200
    assert data["success"] is True
    assert data["result"]["interface"] == "wlan0"
    assert data["result"]["captured_packets"] == 10
    assert data["result"]["alert_count"] == 1
    assert data["result"]["alerts"][0]["type"] == "POSSIBLE_PORT_SCAN"


def test_detection_returns_no_alerts_for_normal_traffic(client, monkeypatch):
    from app.routes import monitoring_routes

    packets = [
        {
            "protocol": "TCP",
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": 443,
            "timestamp": 1000 + index,
            "tcp_flags": "S",
        }
        for index in range(5)
    ]

    def fake_capture(interface, duration, max_packets):
        return {
            "interface": interface,
            "captured_packets": len(packets),
            "packets": packets,
        }

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post("/api/monitoring/detect")

    data = response.get_json()

    assert response.status_code == 200
    assert data["success"] is True
    assert data["result"]["alert_count"] == 0
    assert data["result"]["alerts"] == []


def test_detection_accepts_custom_settings(client, monkeypatch):
    from app.routes import monitoring_routes

    received = {}

    def fake_capture(interface, duration, max_packets):
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
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post(
        "/api/monitoring/detect",
        json={
            "duration": 5,
            "max_packets": 50,
            "time_window": 15,
            "port_threshold": 5,
        },
    )

    data = response.get_json()
	
    assert response.status_code == 200
    assert received == {
        "interface": "wlan0",
        "duration": 5,
        "max_packets": 50,
    }

    assert data["result"]["detection_settings"] == {
        "time_window": 15,
        "port_threshold": 5,
        "arp_time_window": 30,
        "dns_time_window": 60,
        "dns_query_threshold": 100,
        "dns_unique_domain_threshold": 50,
        "dns_nxdomain_threshold": 10,
    }

def test_detection_rejects_invalid_settings_before_capture(
    client,
    monkeypatch,
):
    from app.routes import monitoring_routes

    def fake_capture(*args, **kwargs):
        pytest.fail("Capture should not start with invalid settings.")

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post(
        "/api/monitoring/detect",
        json={"port_threshold": 1},
    )

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_detection_handles_capture_failure(client, monkeypatch):
    from app.routes import monitoring_routes

    def fake_capture(*args, **kwargs):
        raise RuntimeError("Capture failed")

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post("/api/monitoring/detect")

    assert response.status_code == 503
    assert response.get_json()["success"] is False


def test_detection_rejects_unsupported_fields(client):
    response = client.post(
        "/api/monitoring/detect",
        json={"interface": "wlan0"},
    )

    assert response.status_code == 400


def test_detection_rejects_get(client):
    response = client.get("/api/monitoring/detect")

    assert response.status_code == 405
def test_detection_finds_arp_conflict(client, monkeypatch):
    from app.routes import monitoring_routes

    packets = [
        {
            "protocol": "ARP",
            "source_ip": "192.168.1.20",
            "destination_ip": "192.168.1.1",
            "arp_source_mac": "aa:bb:cc:dd:ee:01",
            "arp_destination_mac": "00:00:00:00:00:00",
            "timestamp": 1000.0,
        },
        {
            "protocol": "ARP",
            "source_ip": "192.168.1.20",
            "destination_ip": "192.168.1.1",
            "arp_source_mac": "aa:bb:cc:dd:ee:02",
            "arp_destination_mac": "00:00:00:00:00:00",
            "timestamp": 1001.0,
        },
    ]

    def fake_capture(interface, duration, max_packets):
        return {
            "interface": interface,
            "captured_packets": len(packets),
            "packets": packets,
        }

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post("/api/monitoring/detect")

    data = response.get_json()

    assert response.status_code == 200
    assert data["success"] is True
    assert data["result"]["alert_count"] == 1
    assert len(data["result"]["arp_alerts"]) == 1
    assert data["result"]["arp_alerts"][0]["type"] == "ARP_IP_MAC_CONFLICT"
    assert data["result"]["arp_alerts"][0]["severity"] == "HIGH"


def test_detection_accepts_custom_arp_time_window(client, monkeypatch):
    from app.routes import monitoring_routes

    def fake_capture(interface, duration, max_packets):
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

    response = client.post(
        "/api/monitoring/detect",
        json={"arp_time_window": 45},
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["result"]["detection_settings"]["arp_time_window"] == 45


def test_detection_rejects_invalid_arp_time_window(client, monkeypatch):
    from app.routes import monitoring_routes

    def fake_capture(*args, **kwargs):
        pytest.fail("Capture should not start with invalid ARP settings.")

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post(
        "/api/monitoring/detect",
        json={"arp_time_window": 0},
    )

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_detection_returns_combined_port_scan_and_arp_alerts(
    client,
    monkeypatch,
):
    from app.routes import monitoring_routes

    packets = [
        {
            "protocol": "TCP",
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": port,
            "timestamp": 1000 + index * 0.5,
            "tcp_flags": "S",
        }
        for index, port in enumerate(range(20, 30))
    ]

    packets.extend([
        {
            "protocol": "ARP",
            "source_ip": "192.168.1.30",
            "destination_ip": "192.168.1.1",
            "arp_source_mac": "aa:bb:cc:dd:ee:01",
            "timestamp": 1001.0,
        },
        {
            "protocol": "ARP",
            "source_ip": "192.168.1.30",
            "destination_ip": "192.168.1.1",
            "arp_source_mac": "aa:bb:cc:dd:ee:02",
            "timestamp": 1002.0,
        },
    ])

    def fake_capture(interface, duration, max_packets):
        return {
            "interface": interface,
            "captured_packets": len(packets),
            "packets": packets,
        }

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post("/api/monitoring/detect")
    data = response.get_json()
    result = data["result"]

    assert response.status_code == 200
    assert data["success"] is True
    assert result["captured_packets"] == 12
    assert result["alert_count"] == 2
    assert len(result["port_scan_alerts"]) == 1
    assert len(result["arp_alerts"]) == 1
    assert len(result["alerts"]) == 2
    assert {
        alert["type"] for alert in result["alerts"]
    } == {
        "POSSIBLE_PORT_SCAN",
        "ARP_IP_MAC_CONFLICT",
    }


def test_detection_finds_dns_query_rate_alert(client, monkeypatch):
    from app.routes import monitoring_routes

    packets = [
        {
            "protocol": "DNS",
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "timestamp": timestamp,
            "dns_is_response": False,
            "dns_query_name": f"host{timestamp}.example.com",
            "dns_response_code": None,
        }
        for timestamp in (1, 2, 3)
    ]

    def fake_capture(interface, duration, max_packets):
        return {
            "interface": interface,
            "captured_packets": len(packets),
            "packets": packets,
        }

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post(
        "/api/monitoring/detect",
        json={
    "dns_query_threshold": 3,
    "dns_unique_domain_threshold": 3,
},
    )

    data = response.get_json()
    result = data["result"]

    assert response.status_code == 200
    assert data["success"] is True
    assert len(result["dns_alerts"]) == 2

    alert_types = {
        alert["type"] for alert in result["dns_alerts"]
    }

    assert alert_types == {
        "DNS_QUERY_RATE",
        "DNS_UNIQUE_DOMAIN_SPIKE",
    }

    assert result["alert_count"] == len(result["alerts"])


def test_detection_accepts_custom_dns_settings(client, monkeypatch):
    from app.routes import monitoring_routes

    def fake_capture(interface, duration, max_packets):
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

    response = client.post(
        "/api/monitoring/detect",
        json={
            "dns_time_window": 45,
            "dns_query_threshold": 20,
            "dns_unique_domain_threshold": 15,
            "dns_nxdomain_threshold": 5,
        },
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["success"] is True
    assert data["result"]["detection_settings"] == {
        "time_window": 10,
        "port_threshold": 10,
        "arp_time_window": 30,
        "dns_time_window": 45,
        "dns_query_threshold": 20,
        "dns_unique_domain_threshold": 15,
        "dns_nxdomain_threshold": 5,
    }


def test_detection_rejects_invalid_dns_settings_before_capture(
    client,
    monkeypatch,
):
    from app.routes import monitoring_routes

    def fake_capture(*args, **kwargs):
        pytest.fail("Capture should not start with invalid DNS settings.")

    monkeypatch.setattr(
        monitoring_routes.packet_capture,
        "capture_packets",
        fake_capture,
    )

    response = client.post(
        "/api/monitoring/detect",
        json={"dns_query_threshold": 0},
    )

    assert response.status_code == 400
    assert response.get_json()["success"] is False
