
from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.conf import settings


# Create your models here.

class UserUsername(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    username = models.CharField(max_length=30, unique=True)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserUsername for %s" % self.user


class UserTextName(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    name = models.CharField(max_length=30, unique=True)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserName for %s" % self.user


class UserPrimaryEmail(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    email = models.EmailField(max_length=255, unique=True, null=True, blank=True)

    verified = models.BooleanField(default=False)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "PrimaryEmail for %s" % self.user


class UserVerifiedEmail(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    email = models.EmailField(max_length=255, unique=True)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "VerifiedEmail for %s" % self.user

    class Meta:
        unique_together = ('user', 'email')


class UserUnverifiedEmail(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    email = models.EmailField(max_length=255)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserEmail for %s" % self.user

    class Meta:
        unique_together = ('user', 'email')


class UserPrimaryEmailAuthToken(models.Model):
    user_primary_email = models.ForeignKey(UserPrimaryEmail, on_delete=models.CASCADE, null=True, blank=True)
    uid = models.CharField(max_length=64, unique=True)
    token = models.CharField(max_length=34, unique=True)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        email = self.user_primary_email
        return "AuthToken for %s" % email


class UserUnverifiedEmailAuthToken(models.Model):
    user_unverified_email = models.ForeignKey(UserUnverifiedEmail, on_delete=models.CASCADE, null=True, blank=True)
    uid = models.CharField(max_length=64, unique=True)
    token = models.CharField(max_length=34, unique=True)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        email = self.user_unverified_email
        return "AuthToken for %s" % email


class UserPasswordAuthToken(models.Model):
    user_primary_email = models.ForeignKey(UserPrimaryEmail, on_delete=models.CASCADE, null=True, blank=True)
    user_email = models.ForeignKey(UserEmail, on_delete=models.CASCADE, null=True, blank=True)

    uid = models.CharField(max_length=64, unique=True)
    token = models.CharField(max_length=34, unique=True)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.user_primary_email is not None:
            email = self.user_primary_email
        elif self.user_email is not None:
            email = self.user_email
        else:
            email = "No email"
        return "PasswordAuthToken for %s" % email