from django.contrib.auth.models import AbstractUser
from django.db import models


# Custom user model extending Django's built-in AbstractUser
# This allows adding extra fields to the default user model (like bio, social links, etc.)
class CustomUser(AbstractUser):
    bio = models.TextField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to="profile_img", blank=True, null=True)
    facebook = models.URLField(max_length=255, blank=True, null=True)
    youtube = models.URLField(max_length=255, blank=True, null=True)
    twitter = models.URLField(max_length=255, blank=True, null=True)
    instagram = models.URLField(max_length=255, blank=True, null=True)

  # This will return the username when a CustomUser object is printed
    def __str__(self):
        return self.username
