"""Main entry point for the flask application.
Application servers such as gunicorn must load the application from hello_world_service.main:app.
"""

import logging
from flask import Flask
from . import config, internal, sensor_data, field_data
from .auth.extensions import jwt


def create_app() -> Flask:
    # Create flask app
    app = Flask(__name__)
    # Use gunicorn logger configuration if applicable
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    config.init_config(app)
    configure_extensions(app)

    return app


def configure_extensions(app):
    """Configure flask extensions"""
    jwt.init_app(app)
    app.register_blueprint(internal.blueprint)
    app.register_blueprint(sensor_data.blueprint, url_prefix="/demo_service_bundle/sensor_data")
    app.register_blueprint(field_data.blueprint, url_prefix="/demo_service_bundle/field_data")
