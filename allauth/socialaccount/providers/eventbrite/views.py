"""Views for Eventbrite API v3."""
import requests

from allauth.socialaccount import app_settings
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)

from .provider import EventbriteProvider


class EventbriteOAuth2Adapter(OAuth2Adapter):

    """OAuth2Adapter for Eventbrite API v3."""

    provider_id = EventbriteProvider.id
    settings = app_settings.PROVIDERS.get(provider_id, {})
    authorize_url = 'https://%s/oauth/authorize' % (settings.get(
        'EVENTBRITE_HOSTNAME',
        'www.eventbrite.com'))
    access_token_url = 'https://%s/oauth/token' % (settings.get(
        'EVENTBRITE_HOSTNAME',
        'www.eventbrite.com'))
    profile_url = 'https://%s/v3/users/me/' % (settings.get(
        'EVENTBRITEAPI_HOSTNAME',
        'www.eventbriteapi.com'))

    def complete_login(self, request, app, token, **kwargs):
        """Complete login."""
        resp = requests.get(self.profile_url, params={'token': token.token})
        extra_data = resp.json()
        return self.get_provider().sociallogin_from_response(request,
                                                             extra_data)


oauth2_login = OAuth2LoginView.adapter_view(EventbriteOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(EventbriteOAuth2Adapter)
