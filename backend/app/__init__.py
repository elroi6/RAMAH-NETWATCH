from pathlib import Path

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app(config_class=None):
    app = Flask(__name__, instance_relative_config=True)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    if config_class is None:
        from app.config import Config
        config_class = Config

    app.config.from_object(config_class)

    db.init_app(app)

    from app.models import Device

    @app.cli.command("init-db")
    def init_db():
        """Create database tables."""
        db.create_all()
        print("RAMAH-NETWATCH database initialized.")

    from app.routes.health import health_bp
    from app.routes.device_routes import device_bp
    from app.routes.discovery_routes import discovery_bp
    from app.routes.monitoring_routes import monitoring_bp

    app.register_blueprint(health_bp, url_prefix="/api")
    app.register_blueprint(device_bp, url_prefix="/api")
    app.register_blueprint(discovery_bp, url_prefix="/api")
    app.register_blueprint(monitoring_bp, url_prefix="/api")

    return app
