import logging

from django.conf import settings
from django.contrib.auth.models import User

from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import TAC_PLUS_AUTHEN_TYPES

logger = logging.getLogger(__name__)


#
# settings.py
# TACACSPLUS_HOST = 'localhost'
# TACACSPLUS_PORT = 49
# TACACSPLUS_SECRET = 'super-secret'
# TACACSPLUS_SESSION_TIMEOUT = 5
# TACACSPLUS_AUTH_PROTOCOL = 'ascii'
#

class TACACSPlusBackend:
    '''
    Custom TACACS+ auth backend for Django
    '''
    def _get_or_set_user(self, username, password):
        user, created = User.objects.get_or_create(
            username=username,
            defaults={'is_superuser': False},
        )
        if created:
            logger.debug("Created TACACS+ user %s", username)
        return user

    def authenticate(self, request, username=None, password=None):
        if not settings.TACACSPLUS_HOST:
            return None
        try:
            auth = TACACSClient(
                settings.TACACSPLUS_HOST,
                settings.TACACSPLUS_PORT,
                settings.TACACSPLUS_SECRET,
                timeout=settings.TACACSPLUS_SESSION_TIMEOUT,
            ).authenticate(
                username, password,
                TAC_PLUS_AUTHEN_TYPES[settings.TACACSPLUS_AUTH_PROTOCOL],
            )
        except Exception as e:
            logger.exception("TACACS+ Authentication Error: %s", e)
            return None
        if auth.valid:
            return self._get_or_set_user(username, password)
        if auth.aborted:
            # the server asked for something the client had no answer for,
            # usually a new password because the old one has expired; a
            # login form could ask for it and pass new_password= next time
            logger.info("TACACS+ wants more from %s: %s",
                        username, auth.server_msg.decode('utf-8', 'replace'))
        return None

    def get_user(self, user_id):
        if not settings.TACACSPLUS_HOST:
            return None
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None