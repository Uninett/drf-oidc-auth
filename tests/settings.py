from oidc_auth.test import PEM_PUBLIC_KEY
SECRET_KEY = 'secret'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}
REST_FRAMEWORK = {
    'UNAUTHENTICATED_USER': None,
}
ROOT_URLCONF = 'tests.test_authentication'
OIDC_AUTH = {
    'USERINFO_ENDPOINT': "http://example.com/userinfo",
    'JWT_ISSUERS': {
        'http://example.com': {
            'type': "JWKS",
            'key': 'http://example.com',
            'claims_options': {
                'aud': {
                    'values': ['you'],
                    'essential': True,
                },
            }
        },
        'local': {
            'type': "PEM",
            'key': PEM_PUBLIC_KEY,
            'claims_options': {
                'aud': {
                    'values': ['local_aud'],
                    'essential': True,
                },
            }
        }
    }
}
