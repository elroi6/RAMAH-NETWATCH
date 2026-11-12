from app import create_app


def test_health_endpoint():
    app = create_app()

    app.config["TESTING"] = True

    client = app.test_client()

    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "online"
    assert data["application"] == "RAMAH-NETWATCH"
