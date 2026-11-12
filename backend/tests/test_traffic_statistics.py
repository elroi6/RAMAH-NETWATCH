import pytest

from app.services.traffic_statistics import (
    calculate_traffic_statistics,
)


def test_calculates_basic_traffic_statistics():
    packets = [
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
        {
            "protocol": "TCP",
            "packet_size": 120,
            "source_ip": "192.168.1.30",
            "destination_ip": "192.168.1.20",
        },
    ]

    result = calculate_traffic_statistics(packets)

    assert result["total_packets"] == 3
    assert result["total_bytes"] == 300
    assert result["protocol_distribution"] == {
        "TCP": 2,
        "UDP": 1,
    }
    assert result["protocol_bytes"] == {
        "TCP": 220,
        "UDP": 80,
    }
    assert result["unique_source_ips"] == 2
    assert result["unique_destination_ips"] == 2


def test_handles_empty_packet_list():
    result = calculate_traffic_statistics([])

    assert result["total_packets"] == 0
    assert result["total_bytes"] == 0
    assert result["protocol_distribution"] == {}
    assert result["protocol_bytes"] == {}
    assert result["unique_source_ips"] == 0
    assert result["unique_destination_ips"] == 0
    assert result["top_source_ips"] == []


def test_returns_top_ten_source_ips():
    packets = [
        {
            "protocol": "TCP",
            "packet_size": 64,
            "source_ip": f"192.168.1.{index}",
            "destination_ip": "192.168.1.100",
        }
        for index in range(1, 13)
    ]

    result = calculate_traffic_statistics(packets)

    assert len(result["top_source_ips"]) == 10
    assert result["top_source_ips"][0]["ip_address"] == "192.168.1.1"


def test_rejects_non_list_input():
    with pytest.raises(TypeError):
        calculate_traffic_statistics({})


def test_rejects_invalid_packet_record():
    with pytest.raises(TypeError):
        calculate_traffic_statistics(["invalid"])


def test_rejects_invalid_protocol():
    packets = [{"protocol": "", "packet_size": 64}]

    with pytest.raises(ValueError):
        calculate_traffic_statistics(packets)


def test_rejects_invalid_packet_size():
    for invalid_size in [-1, True, 1.5, "100"]:
        packets = [{"protocol": "TCP", "packet_size": invalid_size}]

        with pytest.raises(ValueError):
            calculate_traffic_statistics(packets)


def test_rejects_invalid_ip_fields():
    packets = [
        {
            "protocol": "TCP",
            "packet_size": 64,
            "source_ip": 123,
        }
    ]

    with pytest.raises(ValueError):
        calculate_traffic_statistics(packets)
