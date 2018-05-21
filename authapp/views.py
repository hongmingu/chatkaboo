from .forms import *
from .models import *
from .utils import *
from .token import *
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.urls import reverse
from django.shortcuts import redirect, render
from django.shortcuts import get_object_or_404, get_list_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.core.mail import EmailMessage
import re
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from django.db import IntegrityError
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.utils.timezone import now, timedelta
import json
from authapp import texts
from authapp import banned
from authapp import options
from authapp import status
import urllib
from urllib.parse import urlparse
import ssl
from bs4 import BeautifulSoup
from django.core.mail import send_mail
from django.http import HttpResponse, HttpResponseNotFound, Http404
from django.db.models import Q
from django.db import transaction
# Create your models here.


def accounts(request):
    return render(request, 'authapp/accounts.html')


'''
password = models.CharField(_('password'), max_length=128)

class AbstractUser(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.
    Username and password are required. Other fields are optional.
    """
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        validators=[username_validator],
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    email = models.EmailField(_('email address'), blank=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)
'''

'''
user = form.save(commit=False)
user.is_active = False
user.save()
'''


def main_create_log_in(request):
    if request.method == 'POST':
        if request.POST['type'] == 'create_first':

            form = UserCreateForm(request.POST)

            name = form.data['name']
            username = form.data['username']
            email = form.data['email']
            data = {
                'name': name,
                'username': username,
                'email': email,
            }

            # Integrity UserEmail and UserUsername

            primary_email_exist = UserPrimaryEmail.objects.filter(email=email).exists()
            verified_email_exist = UserVerifiedEmail.objects.filter(email=email).exists()
            if primary_email_exist or verified_email_exist:
                return render_login_create(request, 'authapp/main_first.html',
                                           texts.EMAIL_ALREADY_USED, LoginForm(), UserCreateForm(data))
            '''
            try:
                primary_email_exist = UserPrimaryEmail.objects.get(Q(email=email), Q(verified=True))
                user_primary_email = UserPrimaryEmail.objects.get(Q(email=email), Q(verified=True))
            except ObjectDoesNotExist:
                pass
            '''
            username_exist = UserUsername.objects.filter(username=username).exists()
            if username_exist:
                return render_login_create(request, 'authapp/main_first.html',
                                           texts.USERNAME_ALREADY_USED, LoginForm(), UserCreateForm(data))

            return render_login_create(request, 'authapp/main_first.html', None, LoginForm(), UserCreateForm(data))

            #######################################################################

        elif request.POST['type'] == 'create_second':
            form = UserCreateForm(request.POST)

            name = form.data['name']
            username = form.data['username']
            email = form.data['email']
            password = form.data['password']
            password_confirm = form.data['password_confirm']

            data = {
                'name': name,
                'username': username,
                'email': email,
            }

            # validating username and password

            primary_email_exist = UserPrimaryEmail.objects.filter(email=email).exists()
            verified_email_exist = UserVerifiedEmail.objects.filter(email=email).exists()
            if primary_email_exist or verified_email_exist:
                return render_login_create(request, 'authapp/main_second.html',
                                           texts.EMAIL_ALREADY_USED, LoginForm(), UserCreateForm(data))

            username_exist = UserUsername.objects.filter(username=username).exists()
            if username_exist:
                return render_login_create(request, 'authapp/main_second.html',
                                           texts.USERNAME_ALREADY_USED, LoginForm(), UserCreateForm(data))
            # regex check

            # password 조건
            password_failure = password_failure_validate(username, password, password_confirm)
            if password_failure:
                clue_message = None
                if password_failure is 1:
                    clue_message = texts.PASSWORD_NOT_THE_SAME
                elif password_failure is 2:
                    clue_message = texts.PASSWORD_LENGTH_PROBLEM
                elif password_failure is 3:
                    clue_message = texts.PASSWORD_EQUAL_USERNAME
                elif password_failure is 4:
                    clue_message = texts.PASSWORD_BANNED
                return render_login_create(request, 'authapp/main_second.html', clue_message,
                                           LoginForm(), UserCreateForm(data))

            # recaptcha part begin

            recaptcha_response = request.POST.get('g-recaptcha-response')
            url = 'https://www.google.com/recaptcha/api/siteverify'
            values = {
                'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
                'response': recaptcha_response
            }
            recaptcha_data = urllib.parse.urlencode(values).encode()
            recaptcha_req = urllib.request.Request(url, data=recaptcha_data)
            recaptcha_response = urllib.request.urlopen(recaptcha_req)
            recaptcha_result = json.loads(recaptcha_response.read().decode())

            if not recaptcha_result['success']:
                return render_login_create(request, 'authapp/main_second.html', texts.RECAPTCHA_CONFIRM_NEED,
                                           LoginForm(), UserCreateForm(data))

            # Then, go to is_valid below
            if form.is_valid():
                new_user_create = None

                new_name = form.cleaned_data['name']
                new_username = form.cleaned_data['username']
                new_password = form.cleaned_data['password']
                new_email = form.cleaned_data['email']

                try:
                    with transaction.atomic():

                        checker_username_result = None
                        counter_username = 0
                        while checker_username_result is None:
                            if counter_username <= 9:
                                try:
                                    id_number = make_id()
                                    new_user_create = User.objects.create_user(
                                        username=id_number,
                                        password=new_password,
                                        is_active=False,
                                    )
                                    checker_username_result = 1

                                except IntegrityError as e:
                                    if 'UNIQUE constraint' in str(e.args):
                                        counter_username = counter_username + 1
                                    else:
                                        return render_login_create(request, 'authapp/main_second.html',
                                                                   texts.CREATING_USER_EXTRA_ERROR, LoginForm(),
                                                                   UserCreateForm(data))
                            else:
                                return render_login_create(request, 'authapp/main_second.html',
                                                           texts.CREATING_USER_EXTRA_ERROR, LoginForm(),
                                                           UserCreateForm(data))

                        new_user_primary_email_create = UserPrimaryEmail.objects.create(
                            user=new_user_create,
                            email=new_email,
                            verified=False,
                            primary=True,
                        )

                        new_user_username = UserUsername.objects.create(
                            user=new_user_create,
                            username=new_username,
                        )
                        new_user_text_name = UserTextName.objects.create(
                            user=new_user_create,
                            name=new_name
                        )

                        checker_email_auth_token_result = None
                        counter_email_auth_token = None
                        uid = None
                        token = None

                        while checker_email_auth_token_result is None:
                            if counter_email_auth_token <= 9:

                                try:
                                    uid = urlsafe_base64_encode(force_bytes(new_user_create.pk))
                                    token = account_activation_token.make_token(new_user_create)
                                    if not UserPrimaryEmailAuthToken.objects.filter(uid=uid, token=token).exists():
                                        UserPrimaryEmailAuthToken.objects.create(
                                            user_primary_email=new_user_primary_email_create,
                                            uid=uid,
                                            token=token,
                                            is_primary=True,
                                        )
                                    checker_email_auth_token_result = 1
                                except IntegrityError as e:
                                    if 'UNIQUE constraint' in str(e.args):
                                        counter_email_auth_token = counter_email_auth_token + 1
                                    else:
                                        return render_login_create(request, 'authapp/main_second.html',
                                                                   texts.EMAIL_CONFIRMATION_EXTRA_ERROR, LoginForm(),
                                                                   UserCreateForm(data))

                        current_site = get_current_site(request)
                        subject = '[' + current_site.domain + ']' + texts.EMAIL_CONFIRMATION_SUBJECT

                        message = render_to_string('authapp/account_activation_email.html', {
                            'username': new_user_username.username,
                            'name': new_user_text_name.name,
                            'email': new_user_primary_email_create.email,
                            'domain': current_site.domain,
                            'uid': uid,
                            'token': token,
                        })

                        # Here needs variable of form.cleaned_data['email']?
                        new_user_email_list = [new_email]

                        send_mail(
                            subject=subject, message=message, from_email=options.DEFAULT_FROM_EMAIL,
                            recipient_list=new_user_email_list
                        )
                # End Transaction
                except Exception:
                    return render_login_create(request, 'authapp/main_second.html',
                                               texts.CREATING_USER_OVERALL_ERROR, LoginForm(),
                                               UserCreateForm(data))

                login(request, new_user_create)
                ####################################################
                ####################################################
                return redirect('/')
            else:
                return render_login_create(request, 'authapp/main_second.html',
                                           texts.CREATING_USER_OVERALL_ERROR, LoginForm(),
                                           UserCreateForm(data))

        elif request.POST['type'] == 'log_in':

            form = LoginForm(request.POST)
            username = form.data['username']
            data = {
                'username': username,
            }

            user_email = None
            user_username = None
            if '@' in username:
                try:
                    user_email = UserPrimaryEmail.objects.get(email=username, primary=True)
                except UserPrimaryEmail.DoesNotExist:
                    pass

                if user_email is None:
                    return render_login_create(request, 'authapp/main_first.html',
                                               texts.LOGIN_EMAIL_NOT_EXIST, LoginForm(data),
                                               UserCreateForm(data))

            else:
                try:
                    user_username = UserUsername.objects.get(username=username)
                except UserUsername.DoesNotExist:
                    pass

                if user_username is None:
                    return render_login_create(request, 'authapp/main_first.html',
                                               texts.LOGIN_USERNAME_NOT_EXIST, LoginForm(data),
                                               UserCreateForm())

            if form.is_valid():
                username = form.cleaned_data['username']
                password = form.cleaned_data['password']
                user = authenticate(username=username, password=password)

                if user is not None:

                    login(request, user)

                    ####################################################
                    ####################################################
                    return redirect(reverse('talk:main'))
                else:
                    data = {
                        'username': username,
                    }
                    return render_login_create(request, 'authapp/main_first.html',
                                               texts.LOGIN_FAILED, LoginForm(data),
                                               UserCreateForm())

    else:
        return render_login_create(request, 'authapp/main_first.html', None, LoginForm(), UserCreateForm())


def email_key_confirm_for_primary(request, uid, token):
    if request.method == "GET":
        try:
            with transaction.atomic():
                try:
                    user_primary_auth_token = UserPrimaryEmailAuthToken.objects.get(uid=uid, token=token)
                except UserPrimaryEmailAuthToken.DoesNotExist:
                    clue = {'message': texts.KEY_NOT_EXIST}
                    return render(request, 'authapp/email_key_confirm.html', {'clue': clue})

                if user_primary_auth_token is not None and not (
                        (now() - user_primary_auth_token.created) <= timedelta(seconds=60 * 10)):
                    user_primary_auth_token.delete()
                    clue = {'message': texts.KEY_EXPIRED}
                    return render(request, 'authapp/email_key_confirm.html', {'clue': clue})

                try:
                    uid = force_text(urlsafe_base64_decode(uid))
                    user = User.objects.get(pk=uid)
                    user_primary_email = user_primary_auth_token.user_primary_email
                except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                    user = None
                    user_primary_email = None

                if user is not None and user_primary_email is not None and user_primary_auth_token is not None \
                        and account_activation_token.check_token(user, token):
                    email = user_primary_email.email
                else:
                    clue = {'message': texts.KEY_EXPIRED}
                    return render(request, 'authapp/email_key_confirm.html', {'clue': clue})
                # 만약 그 사이에 누군가 UserVerifiedEmail 등록해버렸다면 그 때 primary 이메일도 삭제할 것이므로 괜찮다.
                # 결국 이 전에 return 되어 여기까지 오지도 않을 것이다.

                user_primary_email.verified = True
                user.is_active = True

                UserUnverifiedEmail.objects.filter(Q(email=email)).delete()

                user_primary_email.save()
                user.save()
                clue = {'message': texts.KEY_CONFIRM_SUCCESS}
                return render(request, 'authapp/email_key_confirm.html', {'clue': clue})
        except Exception:
            clue = {'message': texts.KEY_OVERALL_FAILED}
            return render(request, 'authapp/email_key_confirm.html', {'clue': clue})


def log_out(request):
    if request.method == "POST":
        logout(request)
        return redirect(reverse('website:main'))
    else:
        logout(request)
        return redirect(reverse('website:main'))


def username_change(request):
    if request.method == "POST":
        if request.is_ajax():
            if request.POST['username']:
                try:
                    with transaction.atomic():
                        new_username = request.POST['username']
                        exist_user_username = UserUsername.objects.filter(username=new_username).exists()
                        if exist_user_username is not None:
                            return clue_json_response(0, texts.USERNAME_ALREADY_USED)
                        username_failure = username_failure_validate(new_username)

                        if username_failure:
                            clue_message = None
                            if username_failure is 1:
                                clue_message = texts.USERNAME_UNAVAILABLE
                            elif username_failure is 2:
                                clue_message = texts.USERNAME_LENGTH_PROBLEM
                            elif username_failure is 3:
                                clue_message = texts.USERNAME_8_CANNOT_DIGITS
                            elif username_failure is 4:
                                clue_message = texts.USERNAME_BANNED

                            return clue_json_response(0, clue_message)
                        user = request.user
                        user_username = user.userusername
                        user_username.username = new_username
                        user_username.save()
                        return clue_json_response(1, texts.USERNAME_CHANGED)

                except Exception:
                    return clue_json_response(0, texts.UNEXPECTED_ERROR)


@ensure_csrf_cookie
def email_add_key_send(request):
    if request.method == 'POST':
        if request.is_ajax():
            if request.POST['email_to_add']:
                try:
                    with transaction.atomic():
                        new_email = request.POST['email_to_add']

                        verified_email_exist = UserVerifiedEmail.objects.filter(email=new_email).exists()
                        primary_verified_email_exist = UserPrimaryEmail.objects.filter(Q(email=new_email),
                                                                                       Q(verified=True))
                        if verified_email_exist or primary_verified_email_exist:
                            return clue_json_response(0, texts.EMAIL_ALREADY_USED)

                        email_validator = email_failure_validate(new_email)
                        if email_validator:
                            if email_validator is 1:
                                return clue_json_response(0, texts.EMAIL_LENGTH_OVER_255)
                            elif email_validator is 2:
                                return clue_json_response(0, texts.EMAIL_UNAVAILABLE)

                        # Now start the registering
                        user = request.user

                        new_user_unverified_email = UserUnverifiedEmail.objects.create(
                            user=user,
                            email=new_email,
                        )

                        checker_email_auth_token_result = None
                        counter_email_auth_token = None
                        uid = None
                        token = None

                        while checker_email_auth_token_result is None:
                            if counter_email_auth_token <= 9:

                                try:
                                    uid = urlsafe_base64_encode(force_bytes(user.pk))
                                    token = account_activation_token.make_token(user)
                                    if not UserUnverifiedEmailAuthToken.objects.filter(uid=uid, token=token).exists():
                                        UserUnverifiedEmailAuthToken.objects.create(
                                            user_unverified_email=new_user_unverified_email,
                                            uid=uid,
                                            token=token,
                                        )
                                    checker_email_auth_token_result = 1
                                except IntegrityError as e:
                                    if 'UNIQUE constraint' in str(e.args):
                                        counter_email_auth_token = counter_email_auth_token + 1
                                    else:
                                        return clue_json_response(0, texts.CREATING_EMAIL_EXTRA_ERROR)

                        current_site = get_current_site(request)
                        subject = '[' + current_site.domain + ']' + texts.EMAIL_CONFIRMATION_SUBJECT

                        message = render_to_string('authapp/account_activation_email.html', {
                            'username': user.userusername.username,
                            'name': user.usertextname.name,
                            'email': new_user_unverified_email.email,
                            'domain': current_site.domain,
                            'uid': uid,
                            'token': token,
                        })

                        # Here needs variable of form.cleaned_data['email']?
                        new_user_email_list = [new_email]

                        send_mail(
                            subject=subject, message=message, from_email=options.DEFAULT_FROM_EMAIL,
                            recipient_list=new_user_email_list
                        )

                        return clue_json_response(1, texts.EMAIL_ADDED_SENT)
                except Exception:
                    return clue_json_response(0, texts.UNEXPECTED_ERROR)



@ensure_csrf_cookie
def unverified_email_key_send(request):
    if request.method == 'POST':
        if request.is_ajax():
            if request.POST['email']:
                try:
                    with transaction.atomic():
                        email = request.POST['email']

                        try:
                            user_unverified_email = UserUnverifiedEmail.objects.get(email=email, user=request.user)
                        except UserUnverifiedEmail.DoesNotExist:
                            return clue_json_response(0, texts.EMAIL_NOT_EXIST)

                        if user_unverified_email is None:
                            pass
                            return clue_json_response(0, texts.EMAIL_NOT_EXIST)
                        else:
                            user = request.user

                            # Start to make token
                            checker_email_auth_token_result = None
                            counter_email_auth_token = None
                            uid = None
                            token = None

                            while checker_email_auth_token_result is None:
                                if counter_email_auth_token <= 9:

                                    try:
                                        uid = urlsafe_base64_encode(force_bytes(user.pk))
                                        token = account_activation_token.make_token(user)

                                        if not UserUnverifiedEmailAuthToken.objects.filter(uid=uid,
                                                                                           token=token).exists():
                                            UserUnverifiedEmailAuthToken.objects.create(
                                                user_unverified_email=user_unverified_email,
                                                uid=uid,
                                                token=token,
                                            )
                                        checker_email_auth_token_result = 1
                                    except IntegrityError as e:
                                        if 'UNIQUE constraint' in str(e.args):
                                            counter_email_auth_token = counter_email_auth_token + 1
                                        else:
                                            return clue_json_response(0, texts.CREATING_EMAIL_EXTRA_ERROR)

                            # Send Email
                            current_site = get_current_site(request)

                            subject = '[' + current_site.domain + ']' + texts.EMAIL_CONFIRMATION_SUBJECT
                            message = render_to_string('authapp/_user_unverified_email_key.html', {
                                'username': user.userusername.username,
                                'name': user.usertextname.name,
                                'email': user_unverified_email.email,
                                'domain': current_site.domain,
                                'uid': uid,
                                'token': token,
                            })

                            email_list = [email]

                            send_mail(
                                subject=subject, message=message, from_email=options.DEFAULT_FROM_EMAIL,
                                recipient_list=email_list
                            )

                            return clue_json_response(1, texts.EMAIL_ADDED_SENT)
                except Exception:
                    return clue_json_response(0, texts.UNEXPECTED_ERROR)



@ensure_csrf_cookie
def primary_email_key_send(request):
    if request.method == 'POST':
        if request.is_ajax():
            if request.POST['email']:
                try:
                    with transaction.atomic():

                        email = request.POST['email']

                        try:
                            user_primary_email = UserPrimaryEmail.objects.get(email=email, user=request.user)
                        except UserUnverifiedEmail.DoesNotExist:
                            return clue_json_response(0, texts.EMAIL_NOT_EXIST)

                        if user_primary_email is None:
                            pass
                            return clue_json_response(0, texts.EMAIL_NOT_EXIST)
                        else:
                            user = request.user

                            # Start to make token
                            checker_email_auth_token_result = None
                            counter_email_auth_token = None
                            uid = None
                            token = None

                            while checker_email_auth_token_result is None:
                                if counter_email_auth_token <= 9:

                                    try:
                                        uid = urlsafe_base64_encode(force_bytes(user.pk))
                                        token = account_activation_token.make_token(user)

                                        if not UserPrimaryEmailAuthToken.objects.filter(uid=uid, token=token).exists():
                                            UserPrimaryEmailAuthToken.objects.create(
                                                user_unverified_email=user_primary_email,
                                                uid=uid,
                                                token=token,
                                            )
                                        checker_email_auth_token_result = 1
                                    except IntegrityError as e:
                                        if 'UNIQUE constraint' in str(e.args):
                                            counter_email_auth_token = counter_email_auth_token + 1
                                        else:
                                            return clue_json_response(0, texts.CREATING_EMAIL_EXTRA_ERROR)

                            # Send Email
                            current_site = get_current_site(request)

                            subject = '[' + current_site.domain + ']' + texts.EMAIL_CONFIRMATION_SUBJECT
                            message = render_to_string('authapp/_user_primary_email_key.html', {
                                'username': user.userusername.username,
                                'name': user.usertextname.name,
                                'email': user_primary_email.email,
                                'domain': current_site.domain,
                                'uid': uid,
                                'token': token,
                            })

                            email_list = [email]

                            send_mail(
                                subject=subject, message=message, from_email=options.DEFAULT_FROM_EMAIL,
                                recipient_list=email_list
                            )

                            return clue_json_response(1, texts.EMAIL_ADDED_SENT)

                except Exception:
                    return clue_json_response(0, texts.UNEXPECTED_ERROR)

def email_remove(request):
    if request.method == "POST":
        if request.is_ajax():
            target_email = request.POST['email']
            if target_email is not None:
                target_user_sub_email = None
                try:
                    target_user_sub_email = UserEmail.objects.get(user_extension=request.user.userextension,
                                                                  email=target_email)
                except UserEmail.DoesNotExist:
                    pass

                if target_user_sub_email is not None:
                    if target_user_sub_email.primary is True:
                        result = None
                        result['success'] = False
                        result['message'] = texts.EMAIL_PRIMARY_CANNOT_BE_REMOVED
                        return JsonResponse(result)
                    else:
                        target_user_sub_email.delete()
                        result = None
                        result['success'] = True
                        result['message'] = texts.EMAIL_REMOVED
                        return JsonResponse(result)


def email_primary(request):
    if request.method == "POST":
        if request.is_ajax():
            email = request.POST['email']
            if email is not None:
                user = request.user
                user_extension = user.userextension
                target_email = None
                try:
                    target_email = UserEmail.objects.get(email=email, user_extension=user_extension)
                except UserEmail.DoesNotExist:
                    pass

                if target_email is not None:
                    if target_email.primary is not True:
                        user_sub_email_already_primary = None
                        try:
                            user_sub_email_already_primary = UserEmail.objects.get(user_extension=user_extension,
                                                                                   primary=True)
                        except UserEmail.DoesNotExist:
                            pass
                        if user_sub_email_already_primary is not None:
                            user_sub_email_already_primary.primary = False
                            user_sub_email_already_primary.save()

                        target_email.primary = True
                        target_email.save()

                        result = None
                        result['success'] = True
                        result['message'] = texts.EMAIL_GET_PRIMARY
                        return JsonResponse(result)
                    else:
                        result = None
                        result['success'] = False
                        result['message'] = texts.EMAIL_ALREADY_PRIMARY
                        return JsonResponse(result)


def password_change(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            username = request.user.userusername.username
            user = authenticate(username=username, password=form.cleaned_data['password'])
            if user is not None:
                new_password = form.cleaned_data['new_password']
                new_password_confirm = form.cleaned_data['new_password_confirm']
                # password 조건
                if not new_password == new_password_confirm:
                    form = PasswordChangeForm()
                    clue = None
                    clue['message'] = texts.PASSWORD_NOT_THE_SAME
                    return render(request, 'authapp/password_check.html', {'form': form, 'clue': clue})

                if len(new_password) > 128 or len(new_password) < 6:
                    clue = None
                    clue['message'] = texts.PASSWORD_LENGTH_PROBLEM
                    form = PasswordChangeForm()
                    return render(request, 'authapp/password_check.html', {'form': form, 'clue': clue})
                if username == new_password:
                    clue = None
                    clue['message'] = texts.PASSWORD_EQUAL_USERNAME
                    form = PasswordChangeForm()
                    return render(request, 'authapp/password_check.html', {'form': form, 'clue': clue})

                user.password = new_password
                user.save()

                return render(request, 'authapp/password_changed.html')
            else:
                form = PasswordChangeForm()
                clue = None
                clue['message'] = texts.PASSWORD_AUTH_FAILED
                return render(request, 'authapp/password_check.html', {'form': form, 'clue': clue})

        else:
            form = PasswordChangeForm()
            clue = None
            clue['message'] = texts.PASSWORD_AUTH_FAILED
            return render(request, 'authapp/password_check.html', {'form': form, 'clue': clue})

    else:
        form = PasswordChangeForm()
        return render(request, 'authapp/password_check.html', {'form': form})


def password_reset(request):
    if request.method == "POST":
        recaptcha_response = request.POST.get('g-recaptcha-response')
        url = 'https://www.google.com/recaptcha/api/siteverify'
        values = {
            'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        recaptcha_data = urllib.parse.urlencode(values).encode()
        recaptcha_req = urllib.request.Request(url, data=recaptcha_data)
        recaptcha_response = urllib.request.urlopen(recaptcha_req)
        recaptcha_result = json.loads(recaptcha_response.read().decode())

        if not recaptcha_result['success']:
            clue = None
            clue['message'] = texts.RECAPTCHA_CONFIRM_NEED
            return render(request, 'authapp/password_reset.html', {'clue': clue})

        form = PasswordResetForm(request.POST)

        username = form.data['username']
        user_email = None
        user_username = None
        if '@' in username:
            try:
                user_email = UserEmail.objects.get(Q(email=username), Q(primary=True) | Q(verified=True))
            except UserEmail.DoesNotExist:
                pass

            if user_email is not None:
                user = user_email.user_extension
                user = user.user

                uid = None
                token = None
                check_token_result = None

                while check_token_result is None:
                    try:
                        uid = urlsafe_base64_encode(force_bytes(user.pk))
                        token = account_activation_token.make_token(user)
                        if not UserPasswordAuthToken.objects.filter(uid=uid, token=token).exists():
                            UserPasswordAuthToken.objects.create(
                                email=user_email,
                                uid=uid,
                                token=token,
                            )
                        check_token_result = 1
                    except IntegrityError as e:
                        if 'unique constraint' in e.message:
                            pass
                        else:

                            clue = {'message': texts.PASSWORD_AUTH_TOKEN_EXTRA_ERROR}
                            return render(request, 'authapp/accounts_change.html', {'clue': clue})

                user_sub_email_list = [user_email.email]
                current_site = get_current_site(request)

                message = render_to_string('authapp/password_reset_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': uid,
                    'token': token,
                })

                subject = '[' + current_site.domain + ']' + texts.EMAIL_CONFIRMATION_SUBJECT

                send_mail(
                    subject=subject, message=message, from_email=options.DEFAULT_FROM_EMAIL,
                    recipient_list=user_sub_email_list
                )
                clue = None
                clue['success'] = True
                clue['message'] = texts.PASSWORD_RESET_EMAIL_SENT
                return JsonResponse(clue)

            else:
                clue = None
                clue['message'] = texts.PASSWORD_RESET_EMAIL_NOT_EXIST
                data = {
                    'username': username,
                }
                form = PasswordResetForm(data)
                return render(request, 'main.html', {'form': form, 'clue': clue})

        else:
            try:
                user_username = UserUsername.objects.get(username=username)
            except UserUsername.DoesNotExist:
                pass

            if user_username is not None:

                user = user_username.user

                user_email = None
                try:
                    user_email = UserEmail.objects.get(user=user, primary=True)
                except UserEmail.DoesNotExist:
                    pass

                uid = None
                token = None
                check_token_result = None

                while check_token_result is None:
                    try:
                        uid = urlsafe_base64_encode(force_bytes(user.pk))
                        token = account_activation_token.make_token(user)
                        if not UserPasswordAuthToken.objects.filter(uid=uid, token=token).exists():
                            UserPasswordAuthToken.objects.create(
                                email=user_email,
                                uid=uid,
                                token=token,
                            )
                        check_token_result = 1
                    except IntegrityError as e:
                        if 'unique constraint' in e.message:
                            pass
                        else:

                            clue = {'message': texts.PASSWORD_AUTH_TOKEN_EXTRA_ERROR}
                            return render(request, 'authapp/accounts_change.html', {'clue': clue})

                user_sub_email_list = [user_email.email]
                current_site = get_current_site(request)

                message = render_to_string('authapp/password_reset_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': uid,
                    'token': token,
                })

                subject = '[' + current_site.domain + ']' + texts.EMAIL_CONFIRMATION_SUBJECT

                send_mail(
                    subject=subject, message=message, from_email=options.DEFAULT_FROM_EMAIL,
                    recipient_list=user_sub_email_list
                )
                clue = None
                clue['success'] = True
                clue['message'] = texts.PASSWORD_RESET_EMAIL_SENT
                return JsonResponse(clue)

            else:
                clue = None
                clue['message'] = texts.PASSWORD_RESET_USERNAME_NOT_EXIST
                data = {
                    'username': username,
                }
                form = PasswordResetForm(data)
                return render(request, 'main.html', {'form': form, 'clue': clue})
    else:
        form = PasswordResetForm()
        return render(request, 'authapp/password_reset.html', {'form': form})


def password_reset_key_confirm(request, uid, token):
    if request.method == "POST":
        try:
            user_auth_token = UserPasswordAuthToken.objects.get(uid=uid, token=token)
        except UserPasswordAuthToken.DoesNotExist:
            clue = {'message': texts.PASSWORD_RESET_KEY_NOT_EXIST}
            return render(request, 'authapp/email_key_confirm.html', {'clue': clue})

        if user_auth_token is not None and not now() - user_auth_token.created <= timedelta(seconds=60 * 10):
            user_auth_token.delete()
            clue = {'message': texts.PASSWORD_RESET_KEY_EXPIRED}
            return render(request, 'authapp/email_key_confirm.html', {'clue': clue})

        try:
            uid = force_text(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid)
            user_sub_email = user_auth_token.email
            user_extension = user.userextension
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
            user_sub_email = None
            user_auth_token = None
            user_extension = None

        if user is not None and user_sub_email is not None \
                and user_auth_token is not None \
                and user_extension is not None \
                and account_activation_token.check_token(user, token):

            form = PasswordResetConfirmForm(request.POST)
            if form.is_valid():
                username = user.userextension.usersubusername.username
                new_password = form.cleaned_data['new_password']
                new_password_confirm = form.cleaned_data['new_password_confirm']

                if not new_password == new_password_confirm:
                    form = PasswordChangeForm()
                    clue = None
                    clue['message'] = texts.PASSWORD_NOT_THE_SAME
                    return render(request, 'authapp/password_check.html', {'form': form, 'clue': clue})

                if len(new_password) > 128 or len(new_password) < 6:
                    clue = None
                    clue['message'] = texts.PASSWORD_LENGTH_PROBLEM
                    form = PasswordChangeForm()
                    return render(request, 'authapp/password_check.html', {'form': form, 'clue': clue})
                if username == new_password:
                    clue = None
                    clue['message'] = texts.PASSWORD_EQUAL_USERNAME
                    form = PasswordChangeForm()
                    return render(request, 'authapp/password_check.html', {'form': form, 'clue': clue})

                email = user_sub_email.email
                if user_extension.verified is False:
                    user_extension.verified = True
                    user_extension.save()
                if user_sub_email.verified is False:
                    user_sub_email.verified = True
                    user_sub_email.save()

                UserEmail.objects.filter(Q(email=email), ~Q(user_extension=user_extension)).delete()

                user.password = new_password
                user.save()

                user_auth_token.delete()

                clue = {'message': texts.KEY_CONFIRM_SUCCESS}

                return render(request, 'authapp/password_changed.html')
            else:
                clue = {'message': texts.KEY_CONFIRM_SUCCESS}
                return render(request, 'authapp/email_key_confirm.html', {'clue': clue})
        else:
            clue = {'message': texts.KEY_OVERALL_FAILED}
            return render(request, 'authapp/email_key_confirm.html', {'clue': clue})
    else:
        form = PasswordResetConfirmForm()
        clue = {'message': texts.KEY_OVERALL_FAILED}
        return render(request, 'authapp/email_key_confirm.html', {'clue': clue})

def deactivate_user(request):
    if request.method == "POST":
        form = PasswordCheckBeforeDeactivationForm(request.POST)
        if form.is_valid():
            user_extension = request.user.userextension
            user = authenticate(username=user_extension.usersubusername.username,
                                password=form.cleaned_data['password'])
            if user is not None:
                user_extension.activated = False
                user_extension.save()
                logout(request)
                return render(request, 'authapp/user_deactivate_done.html')
            else:
                clue = None
                clue['success'] = False
                clue['message'] = texts.PASSWORD_AUTH_FAILED
                form = PasswordCheckBeforeDeactivationForm()
                return render(request, 'authapp/user_deactivate.html', {'form': form, 'clue': clue})
        else:
            clue = None
            clue['success'] = False
            clue['message'] = texts.PASSWORD_AUTH_FAILED
            form = PasswordCheckBeforeDeactivationForm()
            return render(request, 'authapp/user_deactivate.html', {'form': form, 'clue': clue})
    else:
        form = PasswordCheckBeforeDeactivationForm()
        return render(request, 'authapp/user_deactivate.html', {'form': form})


def delete_user(request):
    if request.method == "POST":
        form = PasswordCheckBeforeDeleteForm(request.POST)
        if form.is_valid():
            user_extension = request.user.userextension
            user = authenticate(username=user_extension.usersubusername.username,
                                password=form.cleaned_data['password'])
            if user is not None:
                user_extension.activated = False
                user_extension.save()
                UserDeleteTimer.objects.create(user_extension=user_extension)
                logout(request)
                return render(request, 'authapp/user_delete_done.html')
            else:
                clue = None
                clue['success'] = False
                clue['message'] = texts.PASSWORD_AUTH_FAILED
                form = PasswordCheckBeforeDeleteForm()
                return render(request, 'authapp/user_delete.html', {'form': form, 'clue': clue})
        else:
            clue = None
            clue['success'] = False
            clue['message'] = texts.PASSWORD_AUTH_FAILED
            form = PasswordCheckBeforeDeleteForm()
            return render(request, 'authapp/user_delete.html', {'form': form, 'clue': clue})
    else:
        form = PasswordCheckBeforeDeleteForm()
        return render(request, 'authapp/user_delete.html', {'form': form})
