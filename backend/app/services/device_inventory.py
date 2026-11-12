from datetime import datetime, timezone

from app import db
from app.models import Device


def sync_discovered_devices(discovered_devices):
    created = 0
    updated = 0

    try:
        for data in discovered_devices:
            ip_address = data["ip_address"]

            device = Device.query.filter_by(
                ip_address=ip_address
            ).first()

            if device is None:
                device = Device(ip_address=ip_address)
                db.session.add(device)
                created += 1
            else:
                updated += 1

            for field in (
                "mac_address",
                "hostname",
                "operating_system",
            ):
                value = data.get(field)

                if value is not None:
                    setattr(device, field, value)

            device.status = "online"
            device.last_seen = datetime.now(timezone.utc)

            open_ports = data.get("open_ports")

            if open_ports:
                device.open_ports = open_ports

        db.session.commit()

    except Exception:
        db.session.rollback()
        raise

    return {
        "created": created,
        "updated": updated,
        "total": created + updated,
    }


def sync_device_ports(ip_address, discovered_ports):
    device = Device.query.filter_by(
        ip_address=ip_address
    ).first()

    if device is None:
        raise ValueError("Device not found in inventory.")

    try:
        device.open_ports = discovered_ports
        device.last_seen = datetime.now(timezone.utc)

        db.session.commit()

    except Exception:
        db.session.rollback()
        raise

    return device.to_dict()
