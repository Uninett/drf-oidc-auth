import logging

import requests
import json
import jwt
from authlib.jose import JsonWebKey
from authlib.oidc.discovery import get_well_known_url
from django.contrib.auth import get_user_model
from django.utils.encoding import smart_str
from django.utils.functional import cached_property
from django.utils.translation import gettext as _
from requests import request
from requests.exceptions import HTTPError
from rest_framework.authentication import (BaseAuthentication,
                                           get_authorization_header)
from rest_framework.exceptions import AuthenticationFailed

from .settings import api_settings
from .util import cache

logging.basicConfig()
logger = logging.getLogger(__name__)


def get_user_by_id(request, id_token):
    User = get_user_model()
    try:
        user = User.objects.get_by_natural_key(id_token.get('sub'))
    except User.DoesNotExist:
        msg = _('Invalid Authorization header. User not found.')
        raise AuthenticationFailed(msg)
    return user


class BaseOidcAuthentication(BaseAuthentication):
    @property
    @cache(ttl=api_settings.OIDC_BEARER_TOKEN_EXPIRATION_TIME)
    def oidc_config(self):
        return requests.get(
            get_well_known_url(
                api_settings.OIDC_ENDPOINT,
                external=True
            )
        ).json()


class BearerTokenAuthentication(BaseOidcAuthentication):
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        bearer_token = self.get_bearer_token(request)
        if bearer_token is None:
            return None

        try:
            userinfo = self.get_userinfo(bearer_token)
        except HTTPError:
            msg = _('Invalid Authorization header. Unable to verify bearer token')
            raise AuthenticationFailed(msg)

        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, userinfo)

        return user, userinfo

    def get_bearer_token(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.BEARER_AUTH_HEADER_PREFIX.lower()
        if not auth or smart_str(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _(
                'Invalid Authorization header. Credentials string should not contain spaces.')
            raise AuthenticationFailed(msg)

        return auth[1]

    @cache(ttl=api_settings.OIDC_BEARER_TOKEN_EXPIRATION_TIME)
    def get_userinfo(self, token):
        userinfo_endpoint = self.oidc_config.get('userinfo_endpoint', api_settings.USERINFO_ENDPOINT)
        if not userinfo_endpoint:
            raise AuthenticationFailed(_('Invalid userinfo_endpoint URL. Did not find a URL from OpenID connect '
                                         'discovery metadata nor settings.OIDC_AUTH.USERINFO_ENDPOINT.'))

        response = requests.get(userinfo_endpoint, headers={
            'Authorization': 'Bearer {0}'.format(token.decode('ascii'))})
        response.raise_for_status()

        return response.json()

class JWTToken(dict):
    pass

class JSONWebTokenAuthentication(BaseOidcAuthentication):
    """Token based authentication using the JSON Web Token standard"""

    REQUIRED_CLAIMS = ["exp", "nbf", "aud", "iss"]
    SUPPORTED_ALGORITHMS = ["RS256", "RS384", "RS512"]

    @property
    def claims_options(self):
        _claims_options = {
            'iss': {
                'essential': True,
                'values': [self.issuer]
            }
        }
        for key, value in api_settings.OIDC_CLAIMS_OPTIONS.items():
            _claims_options[key] = value
        return _claims_options

    def authenticate(self, request):
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None
        payload = self.decode_jwt(jwt_value)
        self.validate_claims(payload)

        user = api_settings.OIDC_RESOLVE_USER_FUNCTION(request, payload)

        return user, JWTToken(payload)

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth or smart_str(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided')
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _(
                'Invalid Authorization header. Credentials string should not contain spaces.')
            raise AuthenticationFailed(msg)

        return auth[1]

    def jwks(self):
        return JsonWebKey.import_key_set(self.jwks_data())

    @cache(ttl=api_settings.OIDC_JWKS_EXPIRATION_TIME)
    def jwks_data(self):
        r = request("GET", self.oidc_config['jwks_uri'], allow_redirects=True)
        r.raise_for_status()
        return r.json()

    @cached_property
    def issuer(self):
        return self.oidc_config['issuer']

    def decode_jwt(self, jwt_value):
        """Validates a raw token and returns a decoded token if validation is successful"""
        kid = self.get_kid(jwt_value)
        try:
            validated_token = jwt.decode(
                jwt=jwt_value,
                algorithms=self.SUPPORTED_ALGORITHMS,
                key=self.get_public_key(kid),
                options={"require": self.REQUIRED_CLAIMS},
                audience=api_settings.OIDC_CLAIMS_OPTIONS['aud']['value'],
                issuer=self.issuer,
            )
            return validated_token
        except jwt.exceptions.PyJWTError as e:
            raise AuthenticationFailed(f"Error validating token: {e}")

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
