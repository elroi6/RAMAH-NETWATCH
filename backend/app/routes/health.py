from flask import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "application": "RAMAH-NETWATCH",
        "message": "Network monitoring API is running"
    }), 200
