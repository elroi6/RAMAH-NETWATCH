from flask import Blueprint, jsonify

from app import db
from app.models import Device
from app.services.device_enumerator import enumerate_device
device_bp = Blueprint("devices", __name__)


@device_bp.route("/devices", methods=["GET"])
def get_devices():
    devices = Device.query.order_by(
        Device.last_seen.desc()
    ).all()

    return jsonify({
        "success": True,
        "count": len(devices),
        "devices": [device.to_dict() for device in devices]
    }), 200


@device_bp.route("/devices/<int:device_id>", methods=["GET"])
def get_device(device_id):
    device = db.session.get(Device, device_id)

    if device is None:
        return jsonify({
            "success": False,
            "message": "Device not found"
        }), 404

    return jsonify({
        "success": True,
        "device": device.to_dict()
    }), 200
@device_bp.route(
    "/devices/<int:device_id>/enumerate",
    methods=["POST"]
)
def enumerate_device_route(device_id):
    device = db.session.get(Device, device_id)

    if device is None:
        return jsonify({
            "success": False,
            "message": "Device not found."
        }), 404

    try:
        result = enumerate_device(device.ip_address)

        return jsonify({
            "success": True,
            "message": "Device enumeration completed.",
            "device": result
        }), 200

    except ValueError as exc:
        message = str(exc)

        if message == "Device not found in inventory.":
            return jsonify({
                "success": False,
                "message": message
            }), 404

        return jsonify({
            "success": False,
            "message": "Invalid enumeration target."
        }), 400

    except RuntimeError:
        return jsonify({
            "success": False,
            "message": "Device enumeration could not be completed."
        }), 503
