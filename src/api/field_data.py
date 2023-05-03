"""Field data endpoints
"""

from .auth.extensions import jwt
from flask import Blueprint, jsonify, request
from .utils import load_json_template, strip_private_meta

blueprint = Blueprint('field_data', __name__)
FIELDS = load_json_template("field_fields")
GROUPS = load_json_template("field_groups")


@blueprint.route('/groups', methods=['GET'])
@jwt.requires_auth
def list_groups():
    return jsonify(strip_private_meta(GROUPS)), 200


@blueprint.route("/fields")
@jwt.requires_auth
def list_fields():
    group_id = request.args.get('group_id')
    fields = FIELDS if not group_id else [f for f in FIELDS if f["_meta"]["group_id"] == group_id]
    return jsonify(strip_private_meta(fields)), 200


@blueprint.route('/fields/<field_urn>', methods=['GET'])
@jwt.requires_auth
def get_field(field_urn):
    field = next((f for f in FIELDS if f['urn'] == field_urn), None)
    if not field:
        return '', 404
    return jsonify(strip_private_meta(field)), 200


@blueprint.route('/fields/<field_urn>/crops', methods=['GET'])
@jwt.requires_auth
def get_crop_history(field_urn):
    field = next((f for f in FIELDS if f['urn'] == field_urn), None)
    if not field:
        return '', 404
    if "crop" in field["_meta"]:
        return jsonify([field["_meta"]["crop"]]), 200
    return jsonify([]), 200


@blueprint.route('/fields/<field_urn>/crops/<datestr>', methods=['GET'])
@jwt.requires_auth
def get_crop_details(field_urn, datestr):
    field = next((f for f in FIELDS if f['urn'] == field_urn), None)
    if not field:
        return '', 404
    if "crop" in field["_meta"]:
        return jsonify(field["_meta"]["crop"]), 200
    return '', 204


@blueprint.route('/fields/<field_urn>/crops/', methods=['GET'])
@jwt.requires_auth
def get_current_crop_details(field_urn):
    field = next((f for f in FIELDS if f['urn'] == field_urn), None)
    if not field:
        return '', 404
    if "crop" in field["_meta"]:
        return jsonify(field["_meta"]["crop"]), 200
    return '', 204


@blueprint.route('/fields/<field_urn>/driving_path', methods=['GET'])
@jwt.requires_auth
def driving_path(field_urn):
    field = next((f for f in FIELDS if f['urn'] == field_urn), None)
    if not field:
        return '', 404
    return '', 204


@blueprint.route('/fields/<field_urn>/application_results', methods=['GET'])
@jwt.requires_auth
def get_application_results(field_urn):
    field = next((f for f in FIELDS if f['urn'] == field_urn), None)
    if not field:
        return '', 404
    return jsonify([]), 200


@blueprint.route('/fields/<field_urn>/application_results', methods=['POST'])
@jwt.requires_auth
def add_application_result(field_urn):
    field = next((f for f in FIELDS if f['urn'] == field_urn), None)
    if not field:
        return '', 404
    return '', 501


@blueprint.route('/fields/<field_urn>/application_results/<application_id>', methods=['GET'])
@jwt.requires_auth
def download_application_results(field_urn, application_id):
    return '', 404


@blueprint.route('/subscriptions', methods=['POST'])
@jwt.requires_auth
def subscribe():
    return jsonify({"id": "not-really-implemented"}), 200


@blueprint.route('/subscriptions/<subscription_id>', methods=['PATCH'])
@jwt.requires_auth
def refresh_subscription(subscription_id):
    return jsonify({"id": "not-really-implemented"}), 200


@blueprint.route('/subscriptions/<subscription_id>', methods=['DELETE'])
@jwt.requires_auth
def cancel_subscription(subscription_id):
    return '', 204
