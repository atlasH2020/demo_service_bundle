# Based on flask-jwt-oidc 0.1.5

from flask import request, current_app, _request_ctx_stack, jsonify, g
from jose import jwt
import logging
import requests
from functools import wraps

logger = logging.getLogger('jwt')


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


class JwtHelper(object):
    ALGORITHMS = ["RS256"]

    def __init__(self, app=None):

        # These are all set in the init_app function, but are listed here for easy reference
        self.app = app
        self.well_known_config = None
        self.well_known_obj_cache = None
        self.algorithms = JwtHelper.ALGORITHMS
        self.jwks_uri = None
        self.issuer = None
        #self.audience = None
        self.client_secret = None
        self.cache = None
        self.caching_enabled = False

        self.jwt_oidc_test_mode = False
        self.jwt_oidc_test_keys = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """initialize this extension

        if the config['JWT_OIDC_WELL_KNOWN_CONFIG'] is set, then try to load the JWKS_URI & ISSUER from that
        If it is not set
        attempt to load the JWKS_URI and ISSUE from the application config

        Required settings to function:
        WELL_KNOWN_CONFIG (optional) is this is set, the JWKS_URI & ISSUER will be loaded from there
        JWKS_URI: the endpoint defined for the jwks_keys
        ISSUER: the endpoint for the issuer of the tokens
        ALGORITHMS: only RS256 is supported
        AUDIENCE: the oidc audience (or API_IDENTIFIER)
        CLIENT_SECRET: the shared secret / key assigned to the client (audience)
        """
        self.app = app
        app.config.setdefault('JWT_ROLE_CALLBACK', self._role_claim_extractor)
        self.jwt_oidc_test_mode = app.config.get('JWT_OIDC_TEST_MODE', None)
        #
        ## CHECK IF WE"RE RUNNING IN TEST_MODE!!
        #
        if self.jwt_oidc_test_mode:
            app.logger.debug('JWT MANAGER running in test mode, using locally defined certs & tokens')
            self._setup_default_test_config(app)

            self.issuer = app.config.get('JWT_OIDC_TEST_ISSUER', 'localhost.localdomain')
            self.jwt_oidc_test_keys = app.config.get('JWT_OIDC_TEST_KEYS', None)
            #self.audience = app.config.get('JWT_OIDC_TEST_AUDIENCE', None)
            self.client_secret = app.config.get('JWT_OIDC_TEST_CLIENT_SECRET', None)
            self.jwt_oidc_test_private_key_pem = app.config.get('JWT_OIDC_TEST_PRIVATE_KEY_PEM', None)

            if self.jwt_oidc_test_keys:
                app.logger.debug('local key being used: {}'.format(self.jwt_oidc_test_keys))
            else:
                app.logger.error('Attempting to run JWT Manager with no local key assigned')
                raise Exception('Attempting to run JWT Manager with no local key assigned')

        else:

            self.algorithms = app.config.get('JWT_OIDC_ALGORITHMS', JwtHelper.ALGORITHMS)

            # If the WELL_KNOWN_CONFIG is set, then go fetch the JWKS & ISSUER
            self.well_known_config = app.config.get('JWT_OIDC_WELL_KNOWN_CONFIG', None)
            if self.well_known_config:
                # try to get the jwks & issuer from the well known config
                # jurl = urlopen(url=self.well_known_config)
                # self.well_known_obj_cache = json.loads(jurl.read().decode("utf-8"))
                res = requests.get(self.well_known_config)
                self.well_known_obj_cache = res.json()

                self.jwks_uri = self.well_known_obj_cache['jwks_uri']
                self.issuer = self.well_known_obj_cache['issuer']
            else:

                self.jwks_uri = app.config.get('JWT_OIDC_JWKS_URI', None)
                self.issuer = app.config.get('JWT_OIDC_ISSUER', None)

            # Setup JWKS caching
            self.caching_enabled = app.config.get('JWT_OIDC_CACHING_ENABLED', False)
            if self.caching_enabled:
                from werkzeug.contrib.cache import SimpleCache
                self.cache = SimpleCache(default_timeout=app.config.get('JWT_OIDC_JWKS_CACHE_TIMEOUT', 300))

            #self.audience = app.config.get('JWT_OIDC_AUDIENCE', None)
            self.client_secret = app.config.get('JWT_OIDC_CLIENT_SECRET', None)

        app.logger.debug('JWKS_URI: {}'.format(self.jwks_uri))
        app.logger.debug('ISSUER: {}'.format(self.issuer))
        app.logger.debug('ALGORITHMS: {}'.format(self.algorithms))
        #app.logger.debug('AUDIENCE: {}'.format(self.audience))
        app.logger.debug('CLIENT_SECRET: {}'.format(self.client_secret))
        app.logger.debug('JWT_OIDC_TEST_MODE: {}'.format(self.jwt_oidc_test_mode))
        app.logger.debug('JWT_OIDC_TEST_KEYS: {}'.format(self.jwt_oidc_test_keys))

        # set the auth error handler
        auth_err_handler = app.config.get('JWT_OIDC_AUTH_ERROR_HANDLER', JwtHelper.handle_auth_error)
        app.register_error_handler(AuthError, auth_err_handler)

        app.teardown_appcontext(self.teardown)

    def teardown(self, exception):
        pass
        # ctx = _app_ctx_stack.top
        # if hasattr(ctx, 'cached object'):

    @staticmethod
    def handle_auth_error(ex):
        response = jsonify(ex.error)
        response.status_code = ex.status_code
        return response

    def get_token_auth_header(self):
        """Obtains the access token from the Authorization Header
        """

        auth = request.headers.get("Authorization", None)
        if not auth:
            token = request.cookies.get('access-token')
            if token:
                return token
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

    def contains_role(self, roles):
        """Checks that the listed roles are in the token
           using the registered callback
        Args:
            roles [str,]: Comma separated list of valid roles
            JWT_ROLE_CALLBACK (fn): The callback added to the Flask configuration
        """
        if isinstance(roles, str):
            roles = [roles]
        token = self.get_token_auth_header()
        unverified_claims = jwt.get_unverified_claims(token)
        roles_in_token = current_app.config['JWT_ROLE_CALLBACK'](unverified_claims)
        if any(elem in roles_in_token for elem in roles):
            return True
        return False

    def has_one_of_roles(self, roles):
        """Checks that at least one of the roles are in the token
           using the registered callback
        Args:
            roles [str,]: Comma separated list of valid roles
            JWT_ROLE_CALLBACK (fn): The callback added to the Flask configuration
        """

        def decorated(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                self._require_auth_validation(*args, **kwargs)
                if self.contains_role(roles):
                    return f(*args, **kwargs)
                raise AuthError({"code": "missing_a_valid_role",
                                 "description":
                                     "Missing a role required to access this endpoint"}, 403)

            return wrapper

        return decorated

    def validate_roles(self, required_roles):
        """Checks that the listed roles are in the token
           using the registered callback
        Args:
            required_roles [str,]: Comma separated list of required roles
            JWT_ROLE_CALLBACK (fn): The callback added to the Flask configuration
        """
        if isinstance(required_roles, str):
            required_roles = [required_roles]
        token = self.get_token_auth_header()
        unverified_claims = jwt.get_unverified_claims(token)
        roles_in_token = current_app.config['JWT_ROLE_CALLBACK'](unverified_claims)
        if all(elem in roles_in_token for elem in required_roles):
            return True
        return False

    def requires_roles(self, required_roles):
        """Checks that the listed roles are in the token
           using the registered callback
        Args:
            required_roles [str,]: Comma separated list of required roles
            JWT_ROLE_CALLBACK (fn): The callback added to the Flask configuration
        """

        def decorated(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                self._require_auth_validation(*args, **kwargs)
                if self.validate_roles(required_roles):
                    return f(*args, **kwargs)
                raise AuthError({"code": "missing_required_roles",
                                 "description":
                                     "Missing the role(s) required to access this endpoint"}, 403)

            return wrapper

        return decorated

    def requires_auth(self, f):
        """Validates the Bearer Token
        """

        @wraps(f)
        def decorated(*args, **kwargs):
            self._require_auth_validation(*args, **kwargs)

            return f(*args, **kwargs)

        return decorated

    def _require_auth_validation(self, *args, **kwargs):
        token = self.get_token_auth_header()

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

        rsa_key = self.get_rsa_key(self.get_jwks(), unverified_header["kid"])

        if not rsa_key and self.caching_enabled:
            # Could be key rotation, invalidate the cache and try again
            self.cache.delete('jwks')
            rsa_key = self.get_rsa_key(self.get_jwks(), unverified_header["kid"])

        if not rsa_key:
            raise AuthError({"code": "invalid_header",
                             "description": "Unable to find jwks key referenced in token"}, 401)

        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=self.algorithms,
                #audience=self.audience,
                issuer=self.issuer,
                options={"verify_aud": False}
            )
            _request_ctx_stack.top.current_user = g.jwt_oidc_token_info = payload
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token has expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

    def get_jwks(self):
        if self.jwt_oidc_test_mode:
            return self.jwt_oidc_test_keys

        if self.caching_enabled:
            return self._get_jwks_from_cache()
        else:
            return self._fetch_jwks_from_url()

    def _get_jwks_from_cache(self):
        jwks = self.cache.get('jwks')
        if jwks is None:
            jwks = self._fetch_jwks_from_url()
            self.cache.set('jwks', jwks)
        return jwks

    def _fetch_jwks_from_url(self):
        res = requests.get(self.jwks_uri)
        return res.json()

    def create_jwt(self, claims, header):
        token = jwt.encode(claims, self.jwt_oidc_test_private_key_pem, headers=header, algorithm='RS256')
        return token

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

    @staticmethod
    def _role_claim_extractor(claims):
        roles = claims.get('roles')
        return roles if roles else []

    def roles(self):
        token = self.get_token_auth_header()
        unverified_claims = jwt.get_unverified_claims(token)
        return self._role_claim_extractor(unverified_claims)

    def claim(self, name, unverified_claims=None):
        if not unverified_claims:
            token = self.get_token_auth_header()
            unverified_claims = jwt.get_unverified_claims(token)
        return unverified_claims.get(name)

    def claims(self):
        token = self.get_token_auth_header()
        return jwt.get_unverified_claims(token)

    def get_organization(self, claims=None):
        organizations = self.claim('organizations', claims)
        return organizations[0] if organizations else None

    def get_organizations(self, claims=None):
        return self.claim('organizations', claims)

    def owner_of(self, claims=None):
        return self.claim('owner_of', claims)

    def get_roles(self, claims=None):
        return self.claim('roles', claims)

    def get_user_id(self, claims=None):
        return self.claim('sub', claims)

    def is_owner(self, claims=None):
        organizations = self.get_organizations(claims)
        organization_id = organizations[0] if organizations else None
        return organization_id and organization_id == self.owner_of(claims)

    def is_authenticated(self):
        try:
            self._require_auth_validation()
            return True
        except:
            return False
