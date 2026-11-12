from flask import Blueprint, current_app, jsonify, request

from app.services import packet_capture


monitoring_bp = Blueprint("monitoring", __name__)


@monitoring_bp.route("/monitoring/capture", methods=["POST"])
def capture_network_traffic():
    interface = current_app.config.get("NETWATCH_INTERFACE")

    if not interface:
        return jsonify({
            "success": False,
            "message": "Network interface is not configured."
        }), 500

    if request.data and not request.is_json:
        return jsonify({
            "success": False,
            "message": "Request body must be JSON."
        }), 400

    payload = request.get_json(silent=True) if request.is_json else {}

    if payload is None:
        return jsonify({
            "success": False,
            "message": "Invalid JSON request body."
        }), 400

    if not isinstance(payload, dict):
        return jsonify({
            "success": False,
            "message": "Request body must be a JSON object."
        }), 400

    allowed_fields = {"duration", "max_packets"}

    if set(payload) - allowed_fields:
        return jsonify({
            "success": False,
            "message": "Request contains unsupported fields."
        }), 400

    try:
        result = packet_capture.capture_packets(
            interface,
            duration=payload.get("duration", 10),
            max_packets=payload.get("max_packets", 100),
        )

        return jsonify({
            "success": True,
            "message": "Network traffic capture completed.",
            "result": result,
        }), 200

    except ValueError:
        return jsonify({
            "success": False,
            "message": "Invalid packet capture options."
        }), 400

    except RuntimeError:
        return jsonify({
            "success": False,
            "message": "Network traffic capture could not be completed."
        }), 503
