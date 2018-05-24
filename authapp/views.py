import json
import urllib
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.db import IntegrityError
from django.db import transaction
from django.db.models import Q
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.timezone import now, timedelta
from django.views.decorators.csrf import ensure_csrf_cookie

from authapp import options
from authapp import texts
from .forms import *
from .models import *
from .token import *
from .utils import *


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
            if primary_email_exist:
                return render_with_clue_loginform_createform(request, 'authapp/main_first.html',
                                                             texts.EMAIL_ALREADY_USED, LoginForm(), UserCreateForm(data))

            user_text_name_failure = user_text_name_failure_validate(name)
            if user_text_name_failure:
                clue_message = None
                if user_text_name_failure is 1:
                    clue_message = texts.USER_TEXT_NAME_LENGTH_PROBLEM
                elif user_text_name_failure is 2:
                    clue_message = texts.USER_TEXT_NAME_BANNED
                return render_with_clue_loginform_createform(request, 'authapp/main_first.html',
                                                             clue_message, LoginForm(), UserCreateForm(data))

            user_username_exist = UserUsername.objects.filter(username=username).exists()
            if user_username_exist:
                return render_with_clue_loginform_createform(request, 'authapp/main_first.html',
                                                             texts.USERNAME_ALREADY_USED, LoginForm(), UserCreateForm(data))

            username_failure = username_failure_validate(username)
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

                return render_with_clue_loginform_createform(request, 'authapp/main_first.html',
                                                             clue_message, LoginForm(), UserCreateForm(data))

            return render_with_clue_loginform_createform(request, 'authapp/main_second.html',
                                                         None, LoginForm(), UserCreateForm(data))

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

            user_username_exist = UserUsername.objects.filter(username=username).exists()
            if user_username_exist:
                return render_with_clue_loginform_createform(request, 'authapp/main_second.html',
                                                             texts.USERNAME_ALREADY_USED, LoginForm(), UserCreateForm(data))

            username_failure = username_failure_validate(username)
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

            primary_email_exist = UserPrimaryEmail.objects.filter(email=email).exists()
            if primary_email_exist:
                return render_with_clue_loginform_createform(request, 'authapp/main_second.html',
                                                             texts.EMAIL_ALREADY_USED, LoginForm(), UserCreateForm(data))

            email_failure = email_failure_validate(email)
            if email_failure:
                clue_message = None
                if email_failure is 1:
                    clue_message = texts.EMAIL_UNAVAILABLE
                elif email_failure is 2:
                    clue_message = texts.EMAIL_LENGTH_OVER_255
                return render_with_clue_loginform_createform(request, 'authapp/main_second.html',
                                                             clue_message, LoginForm(), UserCreateForm(data))


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
                return render_with_clue_loginform_createform(request, 'authapp/main_second.html', clue_message,
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

                        checker_username_result = 0
                        counter_username = 0
                        while checker_username_result is 0:
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
                                        return render_with_clue_loginform_createform(request, 'authapp/main_second.html',
                                                                                     texts.CREATING_USER_EXTRA_ERROR, LoginForm(),
                                                                                     UserCreateForm(data))
                            else:
                                return render_with_clue_loginform_createform(request, 'authapp/main_second.html',
                                                                             texts.CREATING_USER_EXTRA_ERROR, LoginForm(),
                                                                             UserCreateForm(data))

                        new_user_primary_email_create = UserPrimaryEmail.objects.create(
                            user=new_user_create,
                            email=new_email,
                        )

                        new_user_username = UserUsername.objects.create(
                            user=new_user_create,
                            username=new_username,
                        )
                        new_user_text_name = UserTextName.objects.create(
                            user=new_user_create,
                            name=new_name
                        )
                        checker_while_loop = 0
                        counter_if_loop = 0
                        uid = urlsafe_base64_encode(force_bytes(new_user_create.pk)).decode()
                        token = account_activation_token.make_token(new_user_create)
                        print(uid)
                        while checker_while_loop is 0:
                            if counter_if_loop <= 9:

                                try:

                                    UserPrimaryEmailAuthToken.objects.create(
                                        user_primary_email=new_user_primary_email_create,
                                        uid=uid,
                                        token=token,
                                        email=new_email,
                                    )
                                    checker_while_loop = 1
                                except IntegrityError as e:
                                    if 'UNIQUE constraint' in str(e.args):
                                        counter_if_loop = counter_if_loop + 1
                                    else:
                                        return render_with_clue_loginform_createform(request, 'authapp/main_second.html',
                                                                                     texts.EMAIL_CONFIRMATION_EXTRA_ERROR, LoginForm(),
                                                                                     UserCreateForm(data))

                        current_site = get_current_site(request)
                        subject = '[' + current_site.domain + ']' + texts.EMAIL_CONFIRMATION_SUBJECT

                        message = render_to_string('authapp/_account_activation_email.html', {
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
                    return render_with_clue_loginform_createform(request, 'authapp/main_second.html',
                                                                 'error', LoginForm(),
                                                                 UserCreateForm(data))

                login(request, new_user_create)
                ####################################################
                ####################################################
                return redirect(reverse('baseapp:user_main', kwargs={'user_username': new_user_username.username}))
            else:
                return render_with_clue_loginform_createform(request, 'authapp/main_second.html',
                                                             'error2', LoginForm(),
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
                    return render_with_clue_loginform_createform_log_in(request, 'authapp/main_first.html',
                                                                 texts.LOGIN_EMAIL_NOT_EXIST, LoginForm(data),
                                                                 UserCreateForm(data))

            else:
                try:
                    user_username = UserUsername.objects.get(username=username)
                except UserUsername.DoesNotExist:
                    pass

                if user_username is None:
                    return render_with_clue_loginform_createform_log_in(request, 'authapp/main_first.html',
                                                                 texts.LOGIN_USERNAME_NOT_EXIST, LoginForm(data),
                                                                 UserCreateForm())

            if form.is_valid():
                try:
                    with transaction.atomic():

                        username = form.cleaned_data['username']
                        password = form.cleaned_data['password']
                        user = authenticate(username=username, password=password)

                        if user is not None:

                            login(request, user)

                            if user.userdelete.is_deleted is True:
                                user.userdelete.is_deleted = False
                                user.userdelete.save()
                            ####################################################
                            ####################################################
                            return redirect(reverse('talk:main'))

                        else:
                            data = {
                                'username': username,
                            }
                            return render_with_clue_loginform_createform_log_in(request, 'authapp/main_first.html',
                                                                         texts.LOGIN_FAILED, LoginForm(data),
                                                                         UserCreateForm())
                except Exception:
                    return render_with_clue_loginform_createform_log_in(request, 'authapp/main_first.html',
                                                                 texts.UNEXPECTED_ERROR, LoginForm(data),
                                                                 UserCreateForm())

    else:
        return render_with_clue_loginform_createform(request, 'authapp/main_first.html', None, LoginForm(), UserCreateForm())


def log_out(request):
    if request.method == "POST":
        logout(request)
        return redirect(reverse('website:main'))
    else:
        logout(request)
        return redirect(reverse('website:main'))


@ensure_csrf_cookie
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
def primary_email_change(request):
    if request.method == "POST":
        if request.is_ajax():
            if request.POST['email']:
                try:
                    with transaction.atomic():

                        new_email = request.POST['email']

                        user_primary_email_exists = UserPrimaryEmail.objects.filter(Q(email=new_email)).exists()
                        if user_primary_email_exists:
                            return clue_json_response(0, texts.EMAIL_ALREADY_USED)

                        user = request.user

                        checker_while_loop = 0
                        counter_if_loop = 0
                        uid = None
                        token = None
                        while checker_while_loop is 0:
                            if counter_if_loop <= 9:

                                try:
                                    uid = urlsafe_base64_encode(force_bytes(user.pk))
                                    token = account_activation_token.make_token(user)
                                    print(str(token))
                                    UserPrimaryEmailAuthToken.objects.create(
                                        user_primary_email=user.userprimaryemail,
                                        uid=uid,
                                        token=token,
                                        email=new_email,
                                    )

                                    checker_while_loop = 1
                                except IntegrityError as e:
                                    if 'UNIQUE constraint' in str(e.args):
                                        counter_if_loop = counter_if_loop + 1
                                    else:
                                        return render_with_clue_one_form(request, 'authapp/password_reset.html',
                                                                         texts.UNEXPECTED_ERROR, PasswordResetForm())

                        # Send Email
                        current_site = get_current_site(request)

                        subject = '[' + current_site.domain + ']' + texts.EMAIL_CONFIRMATION_SUBJECT
                        message = render_to_string('authapp/_user_password_reset_key.html', {
                            'username': user.userusername.username,
                            'name': user.usertextname.name,
                            'email': new_email,
                            'domain': current_site.domain,
                            'uid': uid,
                            'token': token,
                        })

                        email_list = [new_email]

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
                        except UserPrimaryEmail.DoesNotExist:
                            return clue_json_response(0, texts.EMAIL_NOT_EXIST)

                        user = request.user

                        # Start to make token
                        checker_while_loop = 0
                        counter_if_loop = 0
                        uid = None
                        token = None

                        while checker_while_loop is 0:
                            if counter_if_loop <= 9:

                                try:
                                    uid = urlsafe_base64_encode(force_bytes(user.pk))
                                    token = account_activation_token.make_token(user)

                                    UserPrimaryEmailAuthToken.objects.create(
                                        user_unverified_email=user_primary_email,
                                        uid=uid,
                                        token=token,
                                    )
                                    checker_while_loop = 1
                                except IntegrityError as e:
                                    if 'UNIQUE constraint' in str(e.args):
                                        counter_if_loop = counter_if_loop + 1
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


def primary_email_key_confirm(request, uid, token):
    if request.method == "GET":
        try:
            with transaction.atomic():
                try:
                    user_primary_email_auth_token = UserPrimaryEmailAuthToken.objects.get(uid=uid, token=token)
                except UserPrimaryEmailAuthToken.DoesNotExist:
                    clue = {'message': texts.KEY_UNAVAILABLE}
                    return render(request, 'authapp/primary_email_key_confirm.html', {'clue': clue})

                if user_primary_email_auth_token is None \
                        or ((now() - user_primary_email_auth_token.created) > timedelta(seconds=10)) \
                        or not (UserPrimaryEmailAuthToken.objects.filter(
                            user_primary_email=user_primary_email_auth_token.user_primary_email
                        ).last() == user_primary_email_auth_token):
                    clue = {'message': texts.KEY_EXPIRED}
                    return render(request, 'authapp/primary_email_key_confirm.html', {'clue': clue})

                try:
                    uid = force_text(urlsafe_base64_decode(uid))
                    user = User.objects.get(pk=uid)
                    user_primary_email = user_primary_email_auth_token.user_primary_email
                except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                    user = None
                    user_primary_email = None

                if user is None or user_primary_email is None:
                    clue = {'message': texts.KEY_EXPIRED}
                    return render(request, 'authapp/primary_email_key_confirm.html', {'clue': clue})

                # 만약 그 사이에 누군가 UserVerifiedEmail 등록해버렸다면 그 때 primary 이메일도 삭제할 것이므로 괜찮다.
                # 결국 이 전에 return 되어 여기까지 오지도 않을 것이다.
                user_primary_email.email = user_primary_email_auth_token.email
                user.is_active = True
                user_primary_email.save()

                user.save()

                clue = {'message': texts.KEY_CONFIRM_SUCCESS}
                return render(request, 'authapp/primary_email_key_confirm.html', {'clue': clue})
        except Exception:
            clue = {'message': texts.KEY_OVERALL_FAILED}
            return render(request, 'authapp/primary_email_key_confirm.html', {'clue': clue})


def password_change(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            username = request.user.userusername.username
            user = authenticate(username=username, password=form.cleaned_data['password'])
            if user is not None:
                try:
                    with transaction.atomic():
                        new_password = form.cleaned_data['new_password']
                        new_password_confirm = form.cleaned_data['new_password_confirm']
                        # password 조건
                        # password 조건
                        password_failure = password_failure_validate(username, new_password, new_password_confirm)
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
                            return render_with_clue_one_form(request, 'authapp/password_check.html',
                                                             clue_message, PasswordChangeForm())

                        user.password = new_password
                        user.save()
                        return render_with_clue_one_form(request, 'authapp/password_check.html', texts.PASSWORD_CHANGED,
                                                         PasswordChangeForm())
                except Exception:
                    return render_with_clue_one_form(request, 'authapp/password_check.html', texts.UNEXPECTED_ERROR,
                                                     PasswordChangeForm())

            else:
                return render_with_clue_one_form(request, 'authapp/password_check.html', texts.PASSWORD_AUTH_FAILED, PasswordChangeForm())
        else:
            return render_with_clue_one_form(request, 'authapp/password_check.html', texts.PASSWORD_AUTH_FAILED, PasswordChangeForm())
    else:
        return render_with_clue_one_form(request, 'authapp/password_check.html', None, PasswordChangeForm())


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
            return render_with_clue_one_form(request, 'authapp/password_reset.html', texts.RECAPTCHA_CONFIRM_NEED, PasswordResetForm())

        form = PasswordResetForm(request.POST)

        username = form.data['username']
        if '@' in username:
            try:
                user_primary_email = UserPrimaryEmail.objects.get(email=username)
            except UserPrimaryEmail.DoesNotExist:
                return render_with_clue_one_form(request, 'authapp/password_reset.html', texts.LOGIN_EMAIL_NOT_EXIST, PasswordResetForm())
        else:
            try:
                user_username = UserUsername.objects.get(username=username)
            except UserUsername.DoesNotExist:
                return render_with_clue_one_form(request, 'authapp/password_reset.html', texts.LOGIN_USERNAME_NOT_EXIST, PasswordResetForm())
            user_primary_email = UserPrimaryEmail.objects.get(email=user_username.user.userprimaryemail.email)

        try:
            with transaction.atomic():

                user = user_primary_email.user

                checker_while_loop = 0
                counter_if_loop = 0
                uid = None
                token = None

                while checker_while_loop is 0:
                    if counter_if_loop <= 9:

                        try:
                            uid = urlsafe_base64_encode(force_bytes(user.pk))
                            token = account_activation_token.make_token(user)

                            UserPasswordResetToken.objects.create(
                                user_primary_email=user_primary_email,
                                uid=uid,
                                token=token,
                            )
                            checker_while_loop = 1
                        except IntegrityError as e:
                            if 'UNIQUE constraint' in str(e.args):
                                counter_if_loop = counter_if_loop + 1
                            else:
                                return render_with_clue_one_form(request, 'authapp/password_reset.html',
                                                                 texts.UNEXPECTED_ERROR, PasswordResetForm())

                # Send Email
                current_site = get_current_site(request)

                subject = '[' + current_site.domain + ']' + texts.EMAIL_CONFIRMATION_SUBJECT
                message = render_to_string('authapp/_user_password_reset_key.html', {
                    'username': user.userusername.username,
                    'name': user.usertextname.name,
                    'email': user_primary_email.email,
                    'domain': current_site.domain,
                    'uid': uid,
                    'token': token,
                })

                email_list = [user_primary_email.email]

                send_mail(
                    subject=subject, message=message, from_email=options.DEFAULT_FROM_EMAIL,
                    recipient_list=email_list
                )

                return render_with_clue_one_form(request, 'authapp/password_reset.html',
                                                 texts.PASSWORD_RESET_EMAIL_SENT, PasswordResetForm())
        except Exception:
            pass

    else:
        form = PasswordResetForm()
        return render(request, 'authapp/password_reset.html', {'form': form})


def password_reset_key_confirm(request, uid, token):
    if request.method == "GET":
        try:
            user_password_reset_token = UserPasswordResetToken.objects.get(uid=uid, token=token)
        except UserPasswordResetToken.DoesNotExist:
            clue = {'message': texts.KEY_UNAVAILABLE}
            return render(request, 'authapp/primary_email_key_confirm.html', {'clue': clue})

        if not (user_password_reset_token is not None
                and not ((now() - user_password_reset_token.created) <= timedelta(seconds=60 * 10))
                and (UserPasswordResetToken.objects.filter(
                    user_primary_email=user_password_reset_token.user_primary_email
                ).first() == user_password_reset_token)):
            clue = {'message': texts.KEY_EXPIRED}
            return render(request, 'authapp/primary_email_key_confirm.html', {'clue': clue})

        try:
            uid = force_text(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid)
            user_primary_email = user_password_reset_token.user_primary_email
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
            user_primary_email = None

        if not (user is not None and user_primary_email is not None
                and user_password_reset_token is not None
                and account_activation_token.check_token(user, token)):
            clue = {'message': texts.KEY_EXPIRED}
            return render(request, 'authapp/primary_email_key_confirm.html', {'clue': clue})

        # 이러면 비밀번호 새로 입력할 창을 준다.
        form = PasswordChangeForm()
        return render(request, 'authapp/password_change_from_key.html', {'clue': clue, 'form':form})
    # 여기선 새 패스워드 값을 받아서 처리한다.
    elif request.method == "POST":
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['password']
            new_password_confirm = form.cleaned_data['password_confirm']

            try:
                with transaction.atomic():
                    uid = force_text(urlsafe_base64_decode(uid))
                    try:
                        user = User.objects.get(pk=uid)
                    except User.DoesNotExist:
                        form = PasswordChangeForm()
                        return render_with_clue_one_form(request, 'authapp/primary_email_key_confirm.html', texts.USER_NOT_EXIST, form)

                    password_failure = password_failure_validate(user.userusername.username, new_password, new_password_confirm)
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
                        return render_with_clue_one_form(request, 'authapp/primary_email_key_confirm.html',
                                                         clue_message, PasswordChangeForm())

                    user.password = new_password
                    user.save()

                    return redirect('authapp:password_reset_changed_need_login')
            except Exception:
                return render_with_clue_one_form(request, 'authapp/primary_email_key_confirm.html',
                                                 texts.UNEXPECTED_ERROR, PasswordChangeForm())


def deactivate_user(request):
    if request.method == "POST":
        form = PasswordCheckBeforeDeactivationForm(request.POST)
        if form.is_valid():
            user = authenticate(username=request.user.userusername.username,
                                password=form.cleaned_data['password'])
            if user is not None:
                user.is_active = False
                user.save()
                logout(request)
                return render(request, 'authapp/user_deactivate_done.html')
            else:
                return render_with_clue_one_form(request, 'authapp/user_deactivate.html', texts.PASSWORD_AUTH_FAILED, PasswordCheckBeforeDeactivationForm())
        else:
            return render_with_clue_one_form(request, 'authapp/user_deactivate.html', texts.PASSWORD_AUTH_FAILED,
                                             PasswordCheckBeforeDeactivationForm())
    else:
        form = PasswordCheckBeforeDeactivationForm()
        return render(request, 'authapp/user_deactivate.html', {'form': form})


def delete_user(request):
    if request.method == "POST":
        form = PasswordCheckBeforeDeleteForm(request.POST)
        if form.is_valid():
            user = authenticate(username=request.user.userusername.username,
                                password=form.cleaned_data['password'])
            if user is not None:
                user.is_active = False
                user.save()
                logout(request)
                return render(request, 'authapp/user_delete_done.html')
            else:
                return render_with_clue_one_form(request, 'authapp/user_delete.html', texts.PASSWORD_AUTH_FAILED, PasswordCheckBeforeDeleteForm())
        else:
            return render_with_clue_one_form(request, 'authapp/user_delete.html', texts.PASSWORD_AUTH_FAILED,
                                             PasswordCheckBeforeDeleteForm())
    else:
        form = PasswordCheckBeforeDeleteForm()
        return render(request, 'authapp/user_delete.html', {'form': form})
