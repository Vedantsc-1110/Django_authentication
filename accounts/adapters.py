# accounts/adapters.py

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils.crypto import get_random_string

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.utils import user_email

User = get_user_model()

ALLOWED_DOMAIN = "vit.edu"


class CustomAccountAdapter(DefaultAccountAdapter):
    """
    Adapter for normal account (email/password) signup.
    It enforces that email belongs to @vit.edu and sets username = email.
    """

    def clean_email(self, email):
        """
        Called during signup form validation.
        Raise ValidationError to block non-vit emails.
        """
        email = super().clean_email(email)
        if not email:
            raise ValidationError("Email is required.")
        if not email.lower().endswith(f"@{ALLOWED_DOMAIN}"):
            raise ValidationError("You must sign up using your @vit.edu email address.")
        return email

    def save_user(self, request, user, form, commit=True):
        """
        Called to save a new user created via the regular signup form.
        We'll ensure username == email (unique).
        """
        # Let default behavior populate user fields (first_name/last_name/etc)
        user = super().save_user(request, user, form, commit=False)

        # Use email as username (ensures not empty)
        email = (user.email or "").lower()
        base_username = email if email else (form.cleaned_data.get("username") or "")
        username = base_username

        # Ensure unique username
        while User.objects.filter(username=username).exists():
            username = f"{base_username[:25]}_{get_random_string(5)}"

        user.username = username

        if commit:
            user.save()
        return user


from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.exceptions import ImmediateHttpResponse
from django.http import HttpResponseRedirect
from django.urls import reverse

ALLOWED_DOMAIN = "vit.edu"

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):

    def is_open_for_signup(self, request, sociallogin):
        # Extract email from the provider
        email = sociallogin.user.email.lower() if sociallogin.user.email else None

        if not email or not email.endswith(f"@{ALLOWED_DOMAIN}"):
            # Redirect back to login with an error flag
            login_url = reverse("account_login") + "?invalid_domain=1"
            raise ImmediateHttpResponse(HttpResponseRedirect(login_url))

        return True

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)

        email = (user.email or "").lower()
        user.username = email
        return user


    def populate_user(self, request, sociallogin, data):
        """
        Called before saving a user created from social login.
        Ensure username is set to email (unique).
        """
        user = super().populate_user(request, sociallogin, data)

        email = (user.email or "") or data.get("email") or ""
        email = email.lower()

        if email:
            base_username = email
        else:
            # fallback to provider + uid
            provider = sociallogin.account.provider
            uid = sociallogin.account.uid
            base_username = f"{provider}_{uid}"

        username = base_username
        while User.objects.filter(username=username).exists():
            username = f"{base_username[:25]}_{get_random_string(5)}"

        user.username = username
        user.email = email
        return user
