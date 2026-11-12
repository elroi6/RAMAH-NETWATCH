import subprocess

from flask import Blueprint, current_app, jsonify

from app.services import nmap_runner

discovery_bp = Blueprint("discovery", __name__)


@discovery_bp.route("/discovery/start", methods=["POST"])
def start_discovery():
    interface = current_app.config.get("NETWATCH_INTERFACE")

    if not interface:
        return jsonify({
            "success": False,
            "message": "Network interface is not configured."
        }), 500

    try:
        result = nmap_runner.run_network_discovery(interface)

        return jsonify({
            "success": True,
            "message": "Network discovery completed.",
            "result": result
        }), 200

    except ValueError:
        return jsonify({
            "success": False,
            "message": "Invalid network interface or network configuration."
        }), 400

    except subprocess.TimeoutExpired:
        return jsonify({
            "success": False,
            "message": "Network discovery timed out."
        }), 504

    except RuntimeError:
        return jsonify({
            "success": False,
            "message": "Network discovery could not be completed."
        }), 503
