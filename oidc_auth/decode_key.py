from requests import request
import json

import jwt

from rest_framework.exceptions import AuthenticationFailed

from .settings import api_settings
from .util import cache

class DecodeKey(object):
    key_source = None
    token = None

    def __init__(self, token, key_source):
        self.key_source = key_source
        self.token = token

    @property
    def key(self):
        """Returns a key for use with authlib.jose.jwt.decode"""
        pass

class PEMDecodeKey(DecodeKey):

    @property
    def key(self):
        return self.key_source

class JWKSDecodeKey(DecodeKey):

    @property
    def key(self):
        kid = self.get_kid(self.token)
        key = self.get_public_key(kid)
        return key

    @cache(ttl=api_settings.OIDC_JWKS_EXPIRATION_TIME)
    def jwks_data(self):
        r = request("GET", self.key_source, allow_redirects=True)
        r.raise_for_status()
        return json.loads(r.json())

    def get_kid(self, token):
        """Gets the kid value from the header of a raw token"""
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise AuthenticationFailed("Token must include the 'kid' header")
        return kid

    def get_public_key(self, kid):
        """Gets public key from OIDC endpoint that matches kid"""
        jwks = self.jwks_data()
        for jwk in jwks.get("keys"):
            if jwk["kid"] == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        raise AuthenticationFailed(f"Invalid kid '{kid}'")