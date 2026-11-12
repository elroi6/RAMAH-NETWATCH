from flask import Blueprint, current_app, jsonify, request

from app.services import packet_capture
from app.services.port_scan_detector import detect_port_scans
from app.services.traffic_statistics import calculate_traffic_statistics


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

    for field in ("time_window", "port_threshold"):
        if field in allowed_fields and field in payload:
            options[field] = payload[field]

    return options, None


def capture_network_packets(options=None, allowed_fields=None):
    interface = current_app.config.get("NETWATCH_INTERFACE")

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
    }

    options, error = get_capture_options(allowed_fields)

    if error:
        return error

    time_window = options.get("time_window", 10)
    port_threshold = options.get("port_threshold", 10)

    try:
        # Validate detection settings before starting packet capture.
        detect_port_scans(
            [],
            time_window=time_window,
            port_threshold=port_threshold,
        )
    except ValueError:
        return jsonify({
            "success": False,
            "message": "Invalid port scan detection settings."
        }), 400

    capture_result, error = capture_network_packets(options)

    if error:
        return error

    alerts = detect_port_scans(
        capture_result["packets"],
        time_window=time_window,
        port_threshold=port_threshold,
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
            },
            "alerts": alerts,
        },
    }), 200
