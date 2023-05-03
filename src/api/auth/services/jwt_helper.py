import logging
from datetime import datetime
from functools import wraps, lru_cache

import requests
from flask import request, jsonify, g
from jose import jwt

logger = logging.getLogger(__name__)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


class Claims:
    def __init__(self, claims):
        self._claims = claims

    def user_id(self) -> str:
        return self._claims.get('sub', None)

    def preferred_username(self) -> str:
        return self._claims.get('preferred_username', None)

    def email(self) -> str:
        return self._claims.get('email', None)


class JwtHelper(object):
    def __init__(self, app=None, default_claim_class=Claims):
        self.app = app
        self.algorithms = ["RS256"]
        self.jwks_uri = None
        self.issuer = None
        self._claim_class = default_claim_class
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.jwks_uri = app.config.get('JWT_JWKS_URI', None)
        self.issuer = app.config.get('JWT_ISSUER', None)

        app.logger.debug('JWKS_URI: {}'.format(self.jwks_uri))
        app.logger.debug('ISSUER: {}'.format(self.issuer))
        app.logger.debug('ALGORITHMS: {}'.format(self.algorithms))

        # set the auth error handler
        app.register_error_handler(AuthError, JwtHelper.handle_auth_error)

    @staticmethod
    def handle_auth_error(ex):
        response = jsonify(ex.error)
        response.status_code = ex.status_code
        return response

    def get_auth_token(self):
        """Obtains the access token from the Authorization Header
        """
        auth = request.headers.get("Authorization", None)
        if not auth:
            raise AuthError({"code": "authorization_header_missing",
                             "description": "Authorization header is expected"}
                            , 401)

        parts = auth.split()

        if parts[0].lower() != "bearer":
            raise AuthError({"code": "invalid_header",
                             "description": "Authorization header must start with Bearer"}
                            , 401)

        elif len(parts) < 2:
            raise AuthError({"code": "invalid_header",
                             "description": "Token not found after Bearer"}
                            , 401)

        elif len(parts) > 2:
            raise AuthError({"code": "invalid_header",
                             "description": "Authorization header is an invalid token structure"}
                            , 401)

        return parts[1]

    def requires_auth(self, f):
        """Validates the Bearer Token
        """

        @wraps(f)
        def decorated(*args, **kwargs):
            self._require_auth_validation(*args, **kwargs)

            return f(*args, **kwargs)

        return decorated

    def _require_auth_validation(self, *args, **kwargs):
        token = self.get_auth_token()

        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Invalid header. "
                                 "Use an RS256 signed JWT Access Token"}, 401)
        if unverified_header["alg"] != "RS256":
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Invalid header. "
                                 "Use an RS256 signed JWT Access Token"}, 401)
        if not "kid" in unverified_header:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Invalid header. "
                                 "No KID in token header"}, 401)

        rsa_key = self.get_rsa_key(self.get_jwks(datetime.today().date()), unverified_header["kid"])

        if not rsa_key:
            raise AuthError({"code": "invalid_header",
                             "description": "Unable to find jwks key referenced in token"}, 401)

        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                options={"verify_aud": False}
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token has expired"}, 401)
        except jwt.JWTClaimsError as e:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except BaseException:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)
        g.claims = self._claim_class(payload)

    @lru_cache(maxsize=1)
    def get_jwks(self, date):
        """
        Cacheable call dummy parameter that we cache only for 1 day
        :param date:
        :return:
        """
        return requests.get(self.jwks_uri).json()

    def get_rsa_key(self, jwks, kid):
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == kid:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        return rsa_key

    def claims(self):
        return g.claims

    def is_authenticated(self):
        try:
            self._require_auth_validation()
            return True
        except:
            return False
