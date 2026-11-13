
from flask import Blueprint, current_app, jsonify, request

from app.services import nmap_runner, packet_capture
from app.services.arp_anomaly_detector import detect_arp_anomalies
from app.services.dns_anomaly_detector import detect_dns_anomalies
from app.services.port_scan_detector import detect_port_scans
from app.services.traffic_statistics import calculate_traffic_statistics
from app.services.unknown_device_detector import detect_unknown_devices


monitoring_bp = Blueprint("monitoring", __name__)


def get_capture_options(allowed_fields=None):
    if request.data and not request.is_json:
        return None, (
            jsonify({
                "success": False,
                "message": "Request body must be JSON."
            }),
            400,
        )

    payload = request.get_json(silent=True) if request.is_json else {}

    if payload is None:
        return None, (
            jsonify({
                "success": False,
                "message": "Invalid JSON request body."
            }),
            400,
        )

    if not isinstance(payload, dict):
        return None, (
            jsonify({
                "success": False,
                "message": "Request body must be a JSON object."
            }),
            400,
        )

    if allowed_fields is None:
        allowed_fields = {"duration", "max_packets"}

    if set(payload) - allowed_fields:
        return None, (
            jsonify({
                "success": False,
                "message": "Request contains unsupported fields."
            }),
            400,
        )

    options = {
        "duration": payload.get("duration", 10),
        "max_packets": payload.get("max_packets", 100),
    }

    optional_fields = (
        "time_window",
        "port_threshold",
        "arp_time_window",
        "dns_time_window",
        "dns_query_threshold",
        "dns_unique_domain_threshold",
        "dns_nxdomain_threshold",
    )

    for field in optional_fields:
        if field in allowed_fields and field in payload:
            options[field] = payload[field]

    return options, None


def capture_network_packets(options=None, allowed_fields=None):
    interface = current_app.config.get(
        "NETWATCH_CAPTURE_INTERFACE",
        current_app.config.get("NETWATCH_INTERFACE"),
    )

    if not interface:
        return None, (
            jsonify({
                "success": False,
                "message": "Network interface is not configured."
            }),
            500,
        )

    if options is None:
        options, error = get_capture_options(allowed_fields)

        if error:
            return None, error

    try:
        result = packet_capture.capture_packets(
            interface,
            duration=options["duration"],
            max_packets=options["max_packets"],
        )

        return result, None

    except ValueError:
        return None, (
            jsonify({
                "success": False,
                "message": "Invalid packet capture options."
            }),
            400,
        )

    except RuntimeError:
        return None, (
            jsonify({
                "success": False,
                "message": "Network traffic capture could not be completed."
            }),
            503,
        )


@monitoring_bp.route("/monitoring/capture", methods=["POST"])
def capture_network_traffic():
    result, error = capture_network_packets()

    if error:
        return error

    return jsonify({
        "success": True,
        "message": "Network traffic capture completed.",
        "result": result,
    }), 200


@monitoring_bp.route("/monitoring/statistics", methods=["POST"])
def get_network_statistics():
    capture_result, error = capture_network_packets()

    if error:
        return error

    statistics = calculate_traffic_statistics(
        capture_result["packets"]
    )

    return jsonify({
        "success": True,
        "message": "Network traffic statistics calculated.",
        "result": {
            "interface": capture_result["interface"],
            **statistics,
        },
    }), 200


@monitoring_bp.route("/monitoring/detect", methods=["POST"])
def detect_network_threats():
    allowed_fields = {
        "duration",
        "max_packets",
        "time_window",
        "port_threshold",
        "arp_time_window",
        "dns_time_window",
        "dns_query_threshold",
        "dns_unique_domain_threshold",
        "dns_nxdomain_threshold",
    }

    options, error = get_capture_options(allowed_fields)

    if error:
        return error

    time_window = options.get("time_window", 10)
    port_threshold = options.get("port_threshold", 10)
    arp_time_window = options.get("arp_time_window", 30)

    dns_time_window = options.get("dns_time_window", 60)
    dns_query_threshold = options.get("dns_query_threshold", 100)
    dns_unique_domain_threshold = options.get(
        "dns_unique_domain_threshold",
        50,
    )
    dns_nxdomain_threshold = options.get(
        "dns_nxdomain_threshold",
        10,
    )

    try:
        detect_port_scans(
            [],
            time_window=time_window,
            port_threshold=port_threshold,
        )

        detect_arp_anomalies(
            [],
            time_window=arp_time_window,
        )

        detect_dns_anomalies(
            [],
            time_window=dns_time_window,
            query_threshold=dns_query_threshold,
            unique_domain_threshold=dns_unique_domain_threshold,
            nxdomain_threshold=dns_nxdomain_threshold,
        )

    except ValueError:
        return jsonify({
            "success": False,
            "message": "Invalid threat detection settings."
        }), 400

    capture_result, error = capture_network_packets(options)

    if error:
        return error

    packets = capture_result["packets"]

    port_scan_alerts = detect_port_scans(
        packets,
        time_window=time_window,
        port_threshold=port_threshold,
    )

    arp_alerts = detect_arp_anomalies(
        packets,
        time_window=arp_time_window,
    )

    dns_alerts = detect_dns_anomalies(
        packets,
        time_window=dns_time_window,
        query_threshold=dns_query_threshold,
        unique_domain_threshold=dns_unique_domain_threshold,
        nxdomain_threshold=dns_nxdomain_threshold,
    )

    unknown_device_alerts = []

    has_mac_observations = any(
        isinstance(packet, dict)
        and packet.get("source_ip") is not None
        and packet.get("source_mac") is not None
        for packet in packets
    )

    if has_mac_observations:
        try:
            network = nmap_runner.get_interface_network(
                capture_result["interface"]
            )

            unknown_device_alerts = detect_unknown_devices(
                packets,
                network,
            )

        except (ValueError, RuntimeError):
            return jsonify({
                "success": False,
                "message": (
                    "Unable to determine the monitored network "
                    "for device detection."
                )
            }), 503

    alerts = (
        port_scan_alerts
        + arp_alerts
        + dns_alerts
        + unknown_device_alerts
    )

    return jsonify({
        "success": True,
        "message": "Network threat detection completed.",
        "result": {
            "interface": capture_result["interface"],
            "captured_packets": capture_result["captured_packets"],
            "alert_count": len(alerts),
            "detection_settings": {
                "time_window": time_window,
                "port_threshold": port_threshold,
                "arp_time_window": arp_time_window,
                "dns_time_window": dns_time_window,
                "dns_query_threshold": dns_query_threshold,
                "dns_unique_domain_threshold": dns_unique_domain_threshold,
                "dns_nxdomain_threshold": dns_nxdomain_threshold,
            },
            "alerts": alerts,
            "port_scan_alerts": port_scan_alerts,
            "arp_alerts": arp_alerts,
            "dns_alerts": dns_alerts,
            "unknown_device_alerts": unknown_device_alerts,
        },
    }), 200
