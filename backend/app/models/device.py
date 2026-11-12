from datetime import datetime, timezone

from app import db


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)

    ip_address = db.Column(
        db.String(45),
        nullable=False,
        index=True
    )

    mac_address = db.Column(
        db.String(17),
        nullable=True,
        index=True
    )

    hostname = db.Column(
        db.String(255),
        nullable=True
    )

    operating_system = db.Column(
        db.String(255),
        nullable=True
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="unknown"
    )

    open_ports = db.Column(
        db.JSON,
        nullable=False,
        default=list
    )

    first_seen = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    last_seen = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "operating_system": self.operating_system,
            "status": self.status,
            "open_ports": self.open_ports,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }