"""Sensor data endpoints.
"""

from .auth.extensions import jwt
from flask import Blueprint, jsonify
from .utils import load_json_template

blueprint = Blueprint('sensor_data', __name__)
CAPABILITIES = load_json_template("sensor_capabilities")
DATA = load_json_template("sensor_data")


@blueprint.route("/capabilities")
@jwt.requires_auth
def list_capabilities():
    return jsonify(CAPABILITIES), 200


@blueprint.route("/data", methods=["POST"])
@jwt.requires_auth
def get_data():
    return jsonify(DATA), 200
