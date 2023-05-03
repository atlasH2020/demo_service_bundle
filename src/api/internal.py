"""Heartbeat and other utility endpoints
"""

from flask import Blueprint

blueprint = Blueprint('internal', __name__)


@blueprint.route("/heartbeat")
def heartbeat():
    return 'OK', 200
