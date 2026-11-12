import subprocess

from app.services import nmap_runner


def test_start_discovery_success(app, monkeypatch):
    app.config["NETWATCH_INTERFACE"] = "wlan0"

    monkeypatch.setattr(
        nmap_runner,
        "run_network_discovery",
        lambda interface: {
            "interface": interface,
            "network": "172.20.14.0/24",
            "discovered": 7,
            "created": 7,
            "updated": 0,
            "total": 7,
        },
    )

    client = app.test_client()
    response = client.post("/api/discovery/start")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["result"]["discovered"] == 7
    assert data["result"]["interface"] == "wlan0"


def test_start_discovery_handles_timeout(app, monkeypatch):
    app.config["NETWATCH_INTERFACE"] = "wlan0"

    def raise_timeout(interface):
        raise subprocess.TimeoutExpired(
            cmd="nmap",
            timeout=120,
        )

    monkeypatch.setattr(
        nmap_runner,
        "run_network_discovery",
        raise_timeout,
    )

    client = app.test_client()
    response = client.post("/api/discovery/start")

    assert response.status_code == 504
    assert response.get_json()["success"] is False


def test_start_discovery_handles_runtime_error(app, monkeypatch):
    app.config["NETWATCH_INTERFACE"] = "wlan0"

    def raise_error(interface):
        raise RuntimeError("Internal Nmap error")

    monkeypatch.setattr(
        nmap_runner,
        "run_network_discovery",
        raise_error,
    )

    client = app.test_client()
    response = client.post("/api/discovery/start")

    assert response.status_code == 503
    assert response.get_json()["success"] is False


def test_start_discovery_requires_configuration(app):
    app.config["NETWATCH_INTERFACE"] = None

    client = app.test_client()
    response = client.post("/api/discovery/start")

    assert response.status_code == 500
    assert response.get_json()["success"] is False


def test_discovery_endpoint_rejects_get(app):
    client = app.test_client()

    response = client.get("/api/discovery/start")

    assert response.status_code == 405
