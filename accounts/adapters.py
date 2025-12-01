from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string

from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.utils import user_email

User = get_user_model()


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom adapter so that:
    - username is automatically set to the email address
    - no extra signup form (/accounts/3rdparty/signup/) is needed
    """

    def populate_user(self, request, sociallogin, data):
        # Let allauth populate basic fields first (email, first_name, etc.)
        user = super().populate_user(request, sociallogin, data)

        email = user_email(user)  # gets email from user / social data

        if email:
            # Use email as username
            base_username = email
        else:
            # Fallback: provider_uid (very rare that email is missing from Google)
            provider = sociallogin.account.provider
            uid = sociallogin.account.uid
            base_username = f"{provider}_{uid}"

        username = base_username

        # Ensure the username is unique in the DB
        while User.objects.filter(username=username).exists():
            username = f"{base_username[:25]}_{get_random_string(5)}"

        user.username = username
        return user
