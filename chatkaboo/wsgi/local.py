from .base import *

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "chatkaboo.settings.local")

##### Backend settings
'''
AUTHENTICATION_BACKENDS = [
    # Needed to login by username in Django admin, regardless of `allauth`
    'django.contrib.auth.backends.ModelBackend',
]
'''
AUTHENTICATION_BACKENDS = [
    'authapp.backends.EmailOrUsernameAuthBackend',
]