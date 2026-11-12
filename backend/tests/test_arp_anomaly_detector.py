
import pytest

from app.services.arp_anomaly_detector import detect_arp_anomalies


def make_arp_packet(source_ip, source_mac, timestamp):
    return {
        "protocol": "ARP",
        "source_ip": source_ip,
        "arp_source_mac": source_mac,
        "timestamp": timestamp,
    }


def test_detects_conflicting_macs_for_same_ip():
    packets = [
        make_arp_packet(
            "192.168.1.10",
            "00:11:22:33:44:55",
            100,
        ),
        make_arp_packet(
            "192.168.1.10",
            "00:11:22:33:44:66",
            110,
        ),
    ]

    alerts = detect_arp_anomalies(packets)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "ARP_IP_MAC_CONFLICT"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["ip_address"] == "192.168.1.10"
    assert alerts[0]["conflicting_macs"] == [
        "00:11:22:33:44:55",
        "00:11:22:33:44:66",
    ]


def test_ignores_consistent_ip_mac_mapping():
    packets = [
        make_arp_packet("192.168.1.10", "00:11:22:33:44:55", 100),
        make_arp_packet("192.168.1.10", "00:11:22:33:44:55", 105),
    ]

    assert detect_arp_anomalies(packets) == []


def test_ignores_conflicts_outside_time_window():
    packets = [
        make_arp_packet("192.168.1.10", "00:11:22:33:44:55", 100),
        make_arp_packet("192.168.1.10", "00:11:22:33:44:66", 140),
    ]

    assert detect_arp_anomalies(packets, time_window=30) == []


def test_detects_conflict_within_sliding_time_window():
    packets = [
        make_arp_packet("192.168.1.10", "00:11:22:33:44:55", 100),
        make_arp_packet("192.168.1.10", "00:11:22:33:44:66", 140),
        make_arp_packet("192.168.1.10", "00:11:22:33:44:77", 145),
    ]

    alerts = detect_arp_anomalies(packets, time_window=30)

    assert len(alerts) == 1
    assert alerts[0]["conflicting_macs"] == [
        "00:11:22:33:44:66",
        "00:11:22:33:44:77",
    ]


def test_ignores_non_arp_packets():
    packets = [
        {
            "protocol": "TCP",
            "source_ip": "192.168.1.10",
            "timestamp": 100,
        }
    ]

    assert detect_arp_anomalies(packets) == []


def test_handles_empty_packet_list():
    assert detect_arp_anomalies([]) == []


@pytest.mark.parametrize(
    "time_window",
    [0, -1, float("nan"), float("inf"), True, "30"],
)
def test_rejects_invalid_time_window(time_window):
    with pytest.raises(ValueError):
        detect_arp_anomalies([], time_window=time_window)


@pytest.mark.parametrize(
    "source_ip",
    ["invalid-ip", "", None],
)
def test_rejects_invalid_source_ip(source_ip):
    packets = [
        make_arp_packet(
            source_ip,
            "00:11:22:33:44:55",
            100,
        )
    ]

    with pytest.raises(ValueError):
        detect_arp_anomalies(packets)


@pytest.mark.parametrize(
    "source_mac",
    ["invalid-mac", "", None, "00:11:22:33:44"],
)
def test_rejects_invalid_source_mac(source_mac):
    packets = [
        make_arp_packet(
            "192.168.1.10",
            source_mac,
            100,
        )
    ]

    with pytest.raises(ValueError):
        detect_arp_anomalies(packets)


@pytest.mark.parametrize(
    "timestamp",
    [float("nan"), float("inf"), True, "100", None],
)
def test_rejects_invalid_timestamp(timestamp):
    packets = [
        make_arp_packet(
            "192.168.1.10",
            "00:11:22:33:44:55",
            timestamp,
        )
    ]

    with pytest.raises(ValueError):
        detect_arp_anomalies(packets)


def test_rejects_invalid_packet_collection():
    with pytest.raises(TypeError):
        detect_arp_anomalies("not a list")


def test_rejects_non_dictionary_packet():
    with pytest.raises(TypeError):
        detect_arp_anomalies(["not a dictionary"])
