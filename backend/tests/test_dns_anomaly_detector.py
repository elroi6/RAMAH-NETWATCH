import pytest

from app.services.dns_anomaly_detector import detect_dns_anomalies


def make_dns_query(
    source_ip="192.168.1.10",
    timestamp=1.0,
    domain="example.com",
):
    return {
        "protocol": "DNS",
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": "8.8.8.8",
        "dns_is_response": False,
        "dns_query_name": domain,
        "dns_response_code": None,
    }


def make_dns_response(
    client_ip="192.168.1.10",
    timestamp=1.0,
    domain="missing.example",
    response_code=3,
):
    return {
        "protocol": "DNS",
        "timestamp": timestamp,
        "source_ip": "8.8.8.8",
        "destination_ip": client_ip,
        "dns_is_response": True,
        "dns_query_name": domain,
        "dns_response_code": response_code,
    }


def test_detects_excessive_dns_queries():
    packets = [
        make_dns_query(timestamp=1),
        make_dns_query(timestamp=2),
        make_dns_query(timestamp=3),
    ]

    alerts = detect_dns_anomalies(
        packets,
        query_threshold=3,
    )

    alert = next(
        alert for alert in alerts
        if alert["type"] == "DNS_QUERY_RATE"
    )

    assert alert["source_ip"] == "192.168.1.10"
    assert alert["query_count"] == 3
    assert alert["severity"] == "MEDIUM"


def test_does_not_alert_below_dns_query_threshold():
    packets = [
        make_dns_query(timestamp=1),
        make_dns_query(timestamp=2),
    ]

    alerts = detect_dns_anomalies(
        packets,
        query_threshold=3,
    )

    assert not any(
        alert["type"] == "DNS_QUERY_RATE"
        for alert in alerts
    )


def test_dns_query_rate_uses_sliding_time_window():
    packets = [
        make_dns_query(timestamp=1),
        make_dns_query(timestamp=2),
        make_dns_query(timestamp=20),
    ]

    alerts = detect_dns_anomalies(
        packets,
        time_window=5,
        query_threshold=3,
    )

    assert not any(
        alert["type"] == "DNS_QUERY_RATE"
        for alert in alerts
    )


def test_detects_many_unique_domains():
    packets = [
        make_dns_query(timestamp=1, domain="one.example"),
        make_dns_query(timestamp=2, domain="two.example"),
        make_dns_query(timestamp=3, domain="three.example"),
    ]

    alerts = detect_dns_anomalies(
        packets,
        unique_domain_threshold=3,
    )

    alert = next(
        alert for alert in alerts
        if alert["type"] == "DNS_UNIQUE_DOMAIN_SPIKE"
    )

    assert alert["source_ip"] == "192.168.1.10"
    assert alert["unique_domain_count"] == 3


def test_repeated_queries_for_same_domain_are_not_unique_domains():
    packets = [
        make_dns_query(timestamp=1, domain="example.com"),
        make_dns_query(timestamp=2, domain="example.com"),
        make_dns_query(timestamp=3, domain="example.com"),
    ]

    alerts = detect_dns_anomalies(
        packets,
        unique_domain_threshold=3,
    )

    assert not any(
        alert["type"] == "DNS_UNIQUE_DOMAIN_SPIKE"
        for alert in alerts
    )


def test_domain_names_are_normalized():
    packets = [
        make_dns_query(timestamp=1, domain="Example.COM."),
        make_dns_query(timestamp=2, domain="example.com"),
    ]

    alerts = detect_dns_anomalies(
        packets,
        unique_domain_threshold=2,
    )

    assert not any(
        alert["type"] == "DNS_UNIQUE_DOMAIN_SPIKE"
        for alert in alerts
    )


def test_detects_repeated_nxdomain_responses():
    packets = [
        make_dns_response(timestamp=1),
        make_dns_response(timestamp=2),
        make_dns_response(timestamp=3),
    ]

    alerts = detect_dns_anomalies(
        packets,
        nxdomain_threshold=3,
    )

    alert = next(
        alert for alert in alerts
        if alert["type"] == "DNS_NXDOMAIN_SPIKE"
    )

    assert alert["source_ip"] == "192.168.1.10"
    assert alert["nxdomain_count"] == 3


def test_non_nxdomain_responses_do_not_trigger_nxdomain_alert():
    packets = [
        make_dns_response(timestamp=1, response_code=0),
        make_dns_response(timestamp=2, response_code=0),
        make_dns_response(timestamp=3, response_code=0),
    ]

    alerts = detect_dns_anomalies(
        packets,
        nxdomain_threshold=3,
    )

    assert not any(
        alert["type"] == "DNS_NXDOMAIN_SPIKE"
        for alert in alerts
    )


def test_dns_responses_do_not_count_as_queries():
    packets = [
        make_dns_response(timestamp=1),
        make_dns_response(timestamp=2),
        make_dns_response(timestamp=3),
    ]

    alerts = detect_dns_anomalies(
        packets,
        query_threshold=3,
    )

    assert not any(
        alert["type"] == "DNS_QUERY_RATE"
        for alert in alerts
    )


def test_detects_possible_dns_tunneling_indicators():
    long_label = "aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW3xY"

    packets = [
        make_dns_query(
            timestamp=1,
            domain=f"{long_label}.example.com",
        ),
        make_dns_query(
            timestamp=2,
            domain=f"{long_label}A.example.com",
        ),
        make_dns_query(
            timestamp=3,
            domain=f"{long_label}B.example.com",
        ),
    ]

    alerts = detect_dns_anomalies(packets)

    alert = next(
        alert for alert in alerts
        if alert["type"] == "POSSIBLE_DNS_TUNNELING"
    )

    assert alert["source_ip"] == "192.168.1.10"
    assert alert["suspicious_query_count"] == 3
    assert alert["severity"] == "HIGH"


def test_normal_dns_queries_do_not_trigger_tunneling_alert():
    packets = [
        make_dns_query(timestamp=1, domain="google.com"),
        make_dns_query(timestamp=2, domain="example.com"),
        make_dns_query(timestamp=3, domain="wikipedia.org"),
    ]

    alerts = detect_dns_anomalies(packets)

    assert not any(
        alert["type"] == "POSSIBLE_DNS_TUNNELING"
        for alert in alerts
    )


def test_ignores_non_dns_packets():
    packets = [
        {
            "protocol": "TCP",
            "timestamp": 1,
            "source_ip": "192.168.1.10",
        },
        {
            "protocol": "ARP",
            "timestamp": 2,
            "source_ip": "192.168.1.10",
        },
    ]

    assert detect_dns_anomalies(packets) == []


def test_empty_packet_list_returns_no_alerts():
    assert detect_dns_anomalies([]) == []


def test_rejects_invalid_packet_collection():
    with pytest.raises(TypeError):
        detect_dns_anomalies("not a list")


def test_rejects_invalid_packet_record():
    with pytest.raises(TypeError):
        detect_dns_anomalies([None])


@pytest.mark.parametrize(
    "time_window",
    [0, -1, True, "60", float("nan"), float("inf")],
)
def test_rejects_invalid_time_window(time_window):
    with pytest.raises(ValueError):
        detect_dns_anomalies(
            [],
            time_window=time_window,
        )


@pytest.mark.parametrize(
    "threshold_name",
    [
        "query_threshold",
        "unique_domain_threshold",
        "nxdomain_threshold",
        "tunneling_query_threshold",
        "tunneling_label_length",
    ],
)
def test_rejects_invalid_thresholds(threshold_name):
    with pytest.raises(ValueError):
        detect_dns_anomalies(
            [],
            **{threshold_name: 0},
        )


@pytest.mark.parametrize(
    "entropy_threshold",
    [0, -1, 7, True, float("nan"), float("inf")],
)
def test_rejects_invalid_entropy_threshold(entropy_threshold):
    with pytest.raises(ValueError):
        detect_dns_anomalies(
            [],
            tunneling_entropy_threshold=entropy_threshold,
        )


def test_rejects_invalid_dns_timestamp():
    packet = make_dns_query(timestamp=float("nan"))

    with pytest.raises(ValueError):
        detect_dns_anomalies([packet])


def test_rejects_invalid_dns_response_indicator():
    packet = make_dns_query()
    packet["dns_is_response"] = "false"

    with pytest.raises(ValueError):
        detect_dns_anomalies([packet])


def test_rejects_invalid_nxdomain_destination():
    packet = make_dns_response()
    packet["destination_ip"] = None

    with pytest.raises(ValueError):
        detect_dns_anomalies([packet])


def test_rejects_invalid_dns_response_code():
    packet = make_dns_response()
    packet["dns_response_code"] = True

    with pytest.raises(ValueError):
        detect_dns_anomalies([packet])
