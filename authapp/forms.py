from django import forms
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.conf import settings
from authapp.models import UserUsername, UserPrimaryEmail

from PIL import Image
from django.core.files import File
from .models import UserPhoto


class UserCreateForm(forms.ModelForm):

    name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'name'}))
    username = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control', 'placeholder': 'username(id)'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'email'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'password'}))
    password_confirm = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                         'placeholder': 'password_confirm'}))

    class Meta:
        model = User
        fields = ['username', 'email', 'password']


class LoginForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control login-form',
                                                             'placeholder': 'username(id) or email',
                                                             'id': 'id_username_login'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control login-form',
                                                                 'placeholder': 'password',
                                                                 'id': 'id_password_login'}))

    class Meta:
        model = User
        fields = ['username', 'password']


class EmailAddForm(forms.ModelForm):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control',
                                                            'placeholder': 'enter email to add'}))

    class Meta:
        model = User
        fields = ['email']


class PasswordChangeForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                     'placeholder': 'new Password'}))
    new_password_confirm = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                             'placeholder': 'new Password confirm'}))

    class Meta:
        model = User
        fields = ['password']


class PasswordResetForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control',
                                                             'placeholder': 'Username(ID) or Email'}))

    class Meta:
        model = User
        fields = ['username']


class PasswordResetConfirmForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                     'placeholder': 'new Password'}))
    password_confirm = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                             'placeholder': 'new Password confirm'}))

    class Meta:
        model = User
        fields = ['password']


class PasswordCheckBeforeDeactivationForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))

    class Meta:
        model = User
        fields = ['password']


class PasswordCheckBeforeDeleteForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))

    class Meta:
        model = User
        fields = ['password']

class PasswordChangeWithUserPKForm(forms.Form):
    pk = forms.IntegerField(widget=forms.HiddenInput(
        attrs={'class': 'form-control', 'placeholder': 'username(id)'}))
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                     'placeholder': 'new Password'}))
    new_password_confirm = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                             'placeholder': 'new Password confirm'}))

    class Meta:
        model = User
        fields = ['pk', 'password']


class UserPhotoForm(forms.ModelForm):
    x = forms.FloatField(widget=forms.HiddenInput())
    y = forms.FloatField(widget=forms.HiddenInput())
    width = forms.FloatField(widget=forms.HiddenInput())
    height = forms.FloatField(widget=forms.HiddenInput())

    class Meta:
        model = UserPhoto
        fields = ('file_300', 'x', 'y', 'width', 'height', )

class TestPicForm(forms.ModelForm):
    x = forms.FloatField(widget=forms.HiddenInput())
    y = forms.FloatField(widget=forms.HiddenInput())
    width = forms.FloatField(widget=forms.HiddenInput())
    height = forms.FloatField(widget=forms.HiddenInput())
    rotate = forms.FloatField(widget=forms.HiddenInput())

    class Meta:
        from .models import TestPic
        model = TestPic
        fields = ('file', 'file_50', 'x', 'y', 'width', 'height', 'rotate', )

    def save(self):
        user_photo = super(TestPicForm, self).save()
        x = self.cleaned_data.get('x')
        y = self.cleaned_data.get('y')
        width = self.cleaned_data.get('width')
        height = self.cleaned_data.get('height')
        rotate = self.cleaned_data.get('rotate')
        print('x: ' + str(x) + 'y: ' + str(y) + 'rotate: ' + str(rotate) +'width: ' + str(width)+'height: ' + str(height))
        file = user_photo.file
        image = Image.open(file)
        fill_color = 'red'  # your background
        if image.mode in ('RGBA', 'LA'):
            background = Image.new(image.mode[:-1], image.size, fill_color)
            background.paste(image, image.split()[-1])
            image = background
        # image_50 = Image.open(user_photo.file_50)
        cropped_image = image.rotate(-1*rotate, expand=True)
        cropped_image = cropped_image.crop((x, y, x + width, y + height)).resize((300, 300), Image.ANTIALIAS)
        cropped_50_image = image.rotate(rotate).crop((x, y, x + width, y + height)).resize((50, 50), Image.ANTIALIAS)
        cropped_image.save(user_photo.file.path)
        file.seek(0)

        cropped_50_image.save(user_photo.file_50.path)

        return user_photo