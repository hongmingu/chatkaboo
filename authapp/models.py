
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
    is_permitted = models.BooleanField(default=False)

    email = models.EmailField(max_length=255, unique=True, null=True, blank=True)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "PrimaryEmail for %s" % self.user




class UserPrimaryEmailAuthToken(models.Model):
    user_primary_email = models.ForeignKey(UserPrimaryEmail, on_delete=models.CASCADE, null=True, blank=True)
    email = models.EmailField(max_length=255)

    uid = models.CharField(max_length=64)
    token = models.CharField(max_length=34, unique=True)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        email = self.user_primary_email
        return "AuthToken for %s" % email


class UserPasswordResetToken(models.Model):
    user_primary_email = models.ForeignKey(UserPrimaryEmail, on_delete=models.CASCADE, null=True, blank=True)
    email = models.EmailField(max_length=255)

    uid = models.CharField(max_length=64)
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


class UserDelete(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserDelete for %s" % self.user.userusername.username

import uuid
import os

def get_file_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = "%s.%s" % (uuid.uuid4(), ext)
    return os.path.join('uploads/logos', filename)

def get_file_path_50(instance, filename):
    ext = filename.split('.')[-1]
    filename = "%s.%s" % (uuid.uuid4(), ext)
    return os.path.join('uploads/logos/50s', filename)


class UserPhoto(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    file_50 = models.ImageField(null=True, blank=True, default=None, upload_to=get_file_path)
    file_300 = models.ImageField(null=True, blank=True, default=None, upload_to=get_file_path_50)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserPhoto pk: %s, username: %s" % (self.pk, self.user.userusername.username)
from imagekit.models import ProcessedImageField, ImageSpecField
from imagekit.processors import ResizeToFill

def get_avatar_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    return 'avatars/{0}/{1}'.format(instance.id, filename)
class TestPic(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    #여기수정해야함

    file = models.ImageField(null=True, blank=True, default=None, upload_to="photo/%Y/%m/%d")


    file_50 = models.ImageField(null=True, blank=True, default=None, upload_to="photo/%Y/%m/%d")
    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "TestPic for %s" % self.pk
'''

    # def create_thumbnail(self):
    #     # If there is no image associated with this.
    #     # do not create thumbnail
    #     if not self.file:
    #         return
    #
    #     # Set our max thumbnail size in a tuple (max width, max height)
    #     THUMBNAIL_SIZE = (50, 50)
    #
    #     DJANGO_TYPE = self.file.file.content_type
    #     print(DJANGO_TYPE)
    #
    #     if DJANGO_TYPE == 'image/jpeg':
    #         PIL_TYPE = 'jpeg'
    #         FILE_EXTENSION = 'jpg'
    #     elif DJANGO_TYPE == 'image/png':
    #         PIL_TYPE = 'png'
    #         FILE_EXTENSION = 'png'
    #     elif DJANGO_TYPE == 'image/gif':
    #         PIL_TYPE = 'gif'
    #         FILE_EXTENSION = 'gif'
    #     from io import BytesIO
    #     from PIL import Image
    #     from django.core.files.uploadedfile import SimpleUploadedFile
    #     import os
    #     # Open original photo which we want to thumbnail using PIL's Image
    #     image = Image.open(BytesIO(self.file.read()))
    #
    #     # use our PIL Image object to create the thumbnail, which already
    #     image.resize((50, 50), Image.ANTIALIAS)
    #
    #     # Save the thumbnail
    #     temp_handle = BytesIO()
    #     image.save(temp_handle, PIL_TYPE)
    #     temp_handle.seek(0)
    #
    #     # Save image to a SimpleUploadedFile which can be saved into ImageField
    #     print(os.path.split(self.file.name)[-1])
    #     suf = SimpleUploadedFile(os.path.split(self.file.name)[-1],
    #                              temp_handle.read(), content_type=DJANGO_TYPE)
    #     # Save SimpleUploadedFile into image field
    #     print(os.path.splitext(suf.name)[0])
    #     self.file_50.save(
    #         '%s_thumbnail.%s' % (os.path.splitext(suf.name)[0], FILE_EXTENSION),
    #         suf, save=False)

    # def save(self, *args, **kwargs):
    #     self.create_thumbnail()
    #     super(TestPic, self).save()
'''