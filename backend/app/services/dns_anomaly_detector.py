import math
from collections import Counter, defaultdict


DEFAULT_TIME_WINDOW = 60
DEFAULT_QUERY_THRESHOLD = 100
DEFAULT_UNIQUE_DOMAIN_THRESHOLD = 50
DEFAULT_NXDOMAIN_THRESHOLD = 10
DEFAULT_TUNNELING_QUERY_THRESHOLD = 3
DEFAULT_TUNNELING_LABEL_LENGTH = 30
DEFAULT_TUNNELING_ENTROPY_THRESHOLD = 3.5


def _validate_positive_number(value, name):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"Invalid {name}.")


def _validate_positive_integer(value, name):
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
    ):
        raise ValueError(f"Invalid {name}.")


def _normalize_domain(domain):
    if domain is None:
        return None

    if not isinstance(domain, str):
        raise ValueError("Invalid DNS query name.")

    normalized = domain.rstrip(".").lower()

    return normalized or None


def _calculate_entropy(value):
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _has_tunneling_indicator(
    domain,
    label_length,
    entropy_threshold,
):
    if not domain:
        return False

    for label in domain.split("."):
        if (
            len(label) >= label_length
            and _calculate_entropy(label) >= entropy_threshold
        ):
            return True

    return False


def _find_threshold_window(
    observations,
    time_window,
    threshold,
    unique_values=False,
):
    if not observations:
        return None

    observations = sorted(
        observations,
        key=lambda item: item[0],
    )

    left = 0
    value_counts = Counter()

    for right, (timestamp, value) in enumerate(observations):
        if unique_values and value is not None:
            value_counts[value] += 1

        while timestamp - observations[left][0] > time_window:
            old_value = observations[left][1]

            if unique_values and old_value is not None:
                value_counts[old_value] -= 1

                if value_counts[old_value] == 0:
                    del value_counts[old_value]

            left += 1

        if unique_values:
            current_count = len(value_counts)
        else:
            current_count = right - left + 1

        if current_count >= threshold:
            return {
                "count": current_count,
                "first_seen": observations[left][0],
                "last_seen": timestamp,
            }

    return None


def detect_dns_anomalies(
    packets,
    time_window=DEFAULT_TIME_WINDOW,
    query_threshold=DEFAULT_QUERY_THRESHOLD,
    unique_domain_threshold=DEFAULT_UNIQUE_DOMAIN_THRESHOLD,
    nxdomain_threshold=DEFAULT_NXDOMAIN_THRESHOLD,
    tunneling_query_threshold=DEFAULT_TUNNELING_QUERY_THRESHOLD,
    tunneling_label_length=DEFAULT_TUNNELING_LABEL_LENGTH,
    tunneling_entropy_threshold=DEFAULT_TUNNELING_ENTROPY_THRESHOLD,
):
    if not isinstance(packets, list):
        raise TypeError("Expected a list of packet records.")

    _validate_positive_number(time_window, "time window")

    _validate_positive_integer(
        query_threshold,
        "DNS query threshold",
    )
    _validate_positive_integer(
        unique_domain_threshold,
        "unique domain threshold",
    )
    _validate_positive_integer(
        nxdomain_threshold,
        "NXDOMAIN threshold",
    )
    _validate_positive_integer(
        tunneling_query_threshold,
        "tunneling query threshold",
    )
    _validate_positive_integer(
        tunneling_label_length,
        "tunneling label length",
    )
    _validate_positive_number(
        tunneling_entropy_threshold,
        "tunneling entropy threshold",
    )

    if tunneling_entropy_threshold > 6:
        raise ValueError("Invalid tunneling entropy threshold.")

    queries_by_source = defaultdict(list)
    domains_by_source = defaultdict(list)
    nxdomain_by_client = defaultdict(list)
    tunneling_by_source = defaultdict(list)

    for packet in packets:
        if not isinstance(packet, dict):
            raise TypeError("Each packet must be a dictionary.")

        if packet.get("protocol") != "DNS":
            continue

        timestamp = packet.get("timestamp")

        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not math.isfinite(timestamp)
        ):
            raise ValueError("Invalid DNS packet timestamp.")

        is_response = packet.get("dns_is_response")

        if not isinstance(is_response, bool):
            raise ValueError("Invalid DNS response indicator.")

        domain = _normalize_domain(
            packet.get("dns_query_name")
        )

        if is_response is False:
            source_ip = packet.get("source_ip")

            if not isinstance(source_ip, str) or not source_ip:
                raise ValueError("Invalid DNS query source IP.")

            queries_by_source[source_ip].append(
                (float(timestamp), domain)
            )

            if domain:
                domains_by_source[source_ip].append(
                    (float(timestamp), domain)
                )

                if _has_tunneling_indicator(
                    domain,
                    tunneling_label_length,
                    tunneling_entropy_threshold,
                ):
                    tunneling_by_source[source_ip].append(
                        (float(timestamp), domain)
                    )

        else:
            response_code = packet.get("dns_response_code")

            if (
                isinstance(response_code, bool)
                or not isinstance(response_code, int)
            ):
                raise ValueError("Invalid DNS response code.")

            if response_code == 3:
                client_ip = packet.get("destination_ip")

                if not isinstance(client_ip, str) or not client_ip:
                    raise ValueError("Invalid NXDOMAIN destination IP.")

                nxdomain_by_client[client_ip].append(
                    (float(timestamp), domain)
                )

    alerts = []

    for source_ip, observations in queries_by_source.items():
        result = _find_threshold_window(
            observations,
            time_window,
            query_threshold,
        )

        if result:
            alerts.append({
                "type": "DNS_QUERY_RATE",
                "severity": "MEDIUM",
                "source_ip": source_ip,
                "query_count": result["count"],
                "time_window_seconds": time_window,
                "first_seen": result["first_seen"],
                "last_seen": result["last_seen"],
            })

    for source_ip, observations in domains_by_source.items():
        result = _find_threshold_window(
            observations,
            time_window,
            unique_domain_threshold,
            unique_values=True,
        )

        if result:
            alerts.append({
                "type": "DNS_UNIQUE_DOMAIN_SPIKE",
                "severity": "MEDIUM",
                "source_ip": source_ip,
                "unique_domain_count": result["count"],
                "time_window_seconds": time_window,
                "first_seen": result["first_seen"],
                "last_seen": result["last_seen"],
            })

    for client_ip, observations in nxdomain_by_client.items():
        result = _find_threshold_window(
            observations,
            time_window,
            nxdomain_threshold,
        )

        if result:
            alerts.append({
                "type": "DNS_NXDOMAIN_SPIKE",
                "severity": "MEDIUM",
                "source_ip": client_ip,
                "nxdomain_count": result["count"],
                "time_window_seconds": time_window,
                "first_seen": result["first_seen"],
                "last_seen": result["last_seen"],
            })

    for source_ip, observations in tunneling_by_source.items():
        result = _find_threshold_window(
            observations,
            time_window,
            tunneling_query_threshold,
        )

        if result:
            suspicious_domains = sorted({
                domain
                for timestamp, domain in observations
                if (
                    result["first_seen"]
                    <= timestamp
                    <= result["last_seen"]
                )
            })

            alerts.append({
                "type": "POSSIBLE_DNS_TUNNELING",
                "severity": "HIGH",
                "source_ip": source_ip,
                "suspicious_query_count": result["count"],
                "suspicious_domains": suspicious_domains[:5],
                "time_window_seconds": time_window,
                "first_seen": result["first_seen"],
                "last_seen": result["last_seen"],
            })

    return sorted(
        alerts,
        key=lambda alert: (
            alert["type"],
            alert["source_ip"],
        ),
    )
