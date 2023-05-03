"""Extensions registry

All extensions here are used as singletons and
initialized in application factory
"""
from .services.jwt_helper import JwtHelper

jwt = JwtHelper()
