"""Helper functions to laod configuration from a YAML file"""

import os
import sys
from pathlib import Path

import yaml
from jinja2 import Template


def init_config(app):
    app.config.update(SECRET_KEY='6493df0ce87932a4d5d7ed77233128edfdfbb52a605b4098')

    # Load configuration file
    keycloak = {
        'base_url': os.environ.get("KEYCLOAK_BASE_URL", "https://sensorsystems.iais.fraunhofer.de/auth"),
        'realm': os.environ.get("KEYCLOAK_REALM", "demo_service_bundle"),
        'client_id': os.environ.get("KEYCLOAK_CLIENT_ID", "atlas"),
        'client_secret': os.environ.get("KEYCLOAK_CLIENT_SECRET")
    }
    app.config.update(
        OIDC_REQUIRE_VERIFIED_EMAIL=True,
        OIDC_USER_INFO_ENABLED=False,
        OIDC_SCOPES=['openid', 'profile', 'roles'],
        OIDC_INTROSPECTION_AUTH_METHOD='client_secret_post',
        OVERWRITE_REDIRECT_URI=f"{keycloak['base_url']}/oidc_callback",
        OIDC_ID_TOKEN_COOKIE_PATH=keycloak['base_url'],
        OIDC_ID_TOKEN_COOKIE_NAME='oidc',
        OIDC_LOGOUT_URL=f"{keycloak['base_url']}/realms/{keycloak['realm']}/protocol/openid-connect/logout",
        JWT_OIDC_AUDIENCE=keycloak['client_id'],
        JWT_OIDC_CLIENT_SECRET=keycloak['client_secret'],
        JWT_OIDC_ISSUER=f"{keycloak['base_url']}/realms/{keycloak['realm']}",
        JWT_OIDC_JWKS_URI=f"{keycloak['base_url']}/realms/{keycloak['realm']}/protocol/openid-connect/certs"
    )
    client_secrets = client_secrets_template(app, keycloak)
    app.config.update(OIDC_CLIENT_SECRETS=client_secrets)


def load_config(app, config_file: str) -> dict:
    """Loads configuration for the hello world service from a given YAML file.

    :param config_file: Path of the configuration YAML file
    :type config_file: str

    :return: A dictionary of the configuration found in the YAML file.
        May be empty if the file is not found or empty itself.
    :rtype: dict
    """

    config_path = Path(config_file)
    if not config_path.is_file():
        app.logger.error("Could not find configuration file at %s", config_path)
        sys.exit(1)

    with open(config_path, "r") as f:
        config = yaml.safe_load(f.read())

    return config


def client_secrets_template(app, keycloak):
    template = Template("""
    {
      "web": {
        "issuer": "{{ issuer }}",
        "auth_uri": "{{ keycloak.base_url }}/realms/{{ keycloak.realm }}/protocol/openid-connect/auth",
        "client_id": "{{ keycloak.client_id }}",
        "client_secret": "{{ keycloak.client_secret }}",
        "redirect_uris": [
          "https://{{ base_url }}/*"
        ],
        "userinfo_uri": "{{ keycloak.base_url }}/realms/{{ keycloak.realm }}/protocol/openid-connect/userinfo",
        "token_uri": "{{ keycloak.base_url }}/realms/{{ keycloak.realm }}/protocol/openid-connect/token",
        "token_introspection_uri": "{{ keycloak.base_url }}/realms/{{ keycloak.realm }}/protocol/openid-connect/token/introspect"
      }
    }
    """)
    data = template.render(issuer=app.config["JWT_OIDC_ISSUER"], keycloak=keycloak)
    with open('/tmp/client_secrets.json', "w+") as f:
        f.write(data)

    return '/tmp/client_secrets.json'
