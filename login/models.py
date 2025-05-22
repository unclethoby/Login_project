from django.contrib.auth.models import AbstractUser
from django.db import models

# ---------------------- Custom User Model ----------------------
class CustomUser(AbstractUser):
    """
    Extends Django's AbstractUser:
    - Adds an 'is_verified' field to track email verification status.
    """
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        """
        Returns the username as the string representation of the user.
        """
        return self.username
