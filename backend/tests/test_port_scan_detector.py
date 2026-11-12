import pytest

from app.services.port_scan_detector import detect_port_scans


def make_packet(
    source="192.168.1.10",
    destination="192.168.1.20",
    port=22,
    timestamp=1000.0,
    flags="S",
):
    return {
        "protocol": "TCP",
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": port,
        "timestamp": timestamp,
        "tcp_flags": flags,
    }


def test_detects_possible_port_scan():
    packets = [
        make_packet(port=port, timestamp=1000 + index * 0.5)
        for index, port in enumerate(range(20, 31))
    ]

    alerts = detect_port_scans(packets)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "POSSIBLE_PORT_SCAN"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["source_ip"] == "192.168.1.10"
    assert alerts[0]["destination_ip"] == "192.168.1.20"
    assert alerts[0]["unique_destination_ports"] == 10
    assert alerts[0]["syn_packets"] == 10


def test_ignores_normal_tcp_traffic():
    packets = [
        make_packet(port=443, timestamp=1000 + index)
        for index in range(15)
    ]

    assert detect_port_scans(packets) == []


def test_ignores_syn_ack_packets():
    packets = [
        make_packet(
            port=port,
            timestamp=1000 + index,
            flags="SA",
        )
        for index, port in enumerate(range(20, 31))
    ]

    assert detect_port_scans(packets) == []


def test_ignores_udp_packets():
    packets = [
        {
            **make_packet(port=port, timestamp=1000 + index),
            "protocol": "UDP",
        }
        for index, port in enumerate(range(20, 31))
    ]

    assert detect_port_scans(packets) == []


def test_repeated_attempts_to_same_port_do_not_trigger_alert():
    packets = [
        make_packet(port=22, timestamp=1000 + index * 0.1)
        for index in range(20)
    ]

    assert detect_port_scans(packets) == []


def test_ignores_attempts_outside_time_window():
    packets = [
        make_packet(port=port, timestamp=1000 + index * 2)
        for index, port in enumerate(range(20, 31))
    ]

    assert detect_port_scans(packets) == []


def test_does_not_combine_different_destinations():
    packets = [
        make_packet(
            destination="192.168.1.20",
            port=port,
            timestamp=1000 + index,
        )
        for index, port in enumerate(range(20, 26))
    ]

    packets += [
        make_packet(
            destination="192.168.1.30",
            port=port,
            timestamp=1000 + index,
        )
        for index, port in enumerate(range(26, 32))
    ]

    assert detect_port_scans(packets) == []


def test_rejects_invalid_packet_list():
    with pytest.raises(TypeError):
        detect_port_scans({})


def test_rejects_invalid_time_window():
    for value in [0, -1, True, "10"]:
        with pytest.raises(ValueError):
            detect_port_scans([], time_window=value)


def test_rejects_invalid_port_threshold():
    for value in [1, 0, -1, True, 2.5]:
        with pytest.raises(ValueError):
            detect_port_scans([], port_threshold=value)


def test_rejects_invalid_destination_port():
    packets = [make_packet(port=70000)]

    with pytest.raises(ValueError):
        detect_port_scans(packets)


def test_rejects_invalid_timestamp():
    packets = [make_packet(timestamp="invalid")]

    with pytest.raises(ValueError):
        detect_port_scans(packets)


def test_rejects_invalid_tcp_flags():
    packets = [make_packet(flags=123)]

    with pytest.raises(ValueError):
        detect_port_scans(packets)


def test_detects_scan_at_exact_time_window_boundary():
    packets = [
        make_packet(port=port, timestamp=1000 + index)
        for index, port in enumerate(range(20, 30))
    ]

    alerts = detect_port_scans(packets)

    assert len(alerts) == 1
    assert alerts[0]["unique_destination_ports"] == 10
    
def test_rejects_non_finite_time_window():
    for value in [float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(ValueError):
            detect_port_scans([], time_window=value)


def test_rejects_non_finite_timestamp():
    for value in [float("nan"), float("inf"), float("-inf")]:
        packets = [make_packet(timestamp=value)]

        with pytest.raises(ValueError):
            detect_port_scans(packets)
