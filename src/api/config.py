"""Helper functions to laod configuration from a YAML file"""

import os
import logging

logger = logging.getLogger(__name__)


def init_config(app):
    logging.info("init_config")
    app.config.update(
        SECRET_KEY='6493df0ce87932a4d5d7ed77233128edfdfbb52a605b4098',
        JWT_ISSUER=os.environ.get("JWT_ISSUER"),
        JWT_JWKS_URI=os.environ.get("JWT_JWKS_URI")
    )
    logging.info(f"Using issuer {app.config['JWT_ISSUER']}")
