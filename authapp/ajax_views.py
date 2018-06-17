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
from django.http import JsonResponse

from authapp import options
from authapp import texts
from .forms import *
from .models import *
from .token import *
from .utils import *
from django.contrib.auth import update_session_auth_hash
from django.utils.html import escape, _js_escapes, normalize_newlines

# Create your models here.

@ensure_csrf_cookie
def re_settings(request):
    if request.method == "POST":
        if request.user.is_authenticated:
            if request.is_ajax():

                if request.POST.get('command', None) is None:
                    return JsonResponse({'res': 2})

                elif request.POST.get('command', None) == 'name':
                    new_user_text_name = request.POST.get('name', None)
                    if new_user_text_name is not None:

                        user_text_name_failure = user_text_name_failure_validate(new_user_text_name)
                        if user_text_name_failure:
                            clue_message = None
                            if user_text_name_failure is 1:
                                clue_message = texts.USER_TEXT_NAME_LENGTH_PROBLEM
                            return JsonResponse({'res': 0, 'message': clue_message})

                        try:
                            with transaction.atomic():
                                user_text_name = request.user.usertextname
                                user_text_name.name = new_user_text_name
                                user_text_name.save()
                        except Exception:
                            return JsonResponse({'res': 0, 'message': texts.UNEXPECTED_ERROR})

                        return JsonResponse({'res': 1, 'name': escape(new_user_text_name)})

                elif request.POST.get('command', None) == 'username':
                    new_user_username = request.POST.get('username', None)
                    if new_user_username is not None:
                        new_user_username = new_user_username.lower()

                        user_username_exist = UserUsername.objects.filter(username=new_user_username).exists()
                        if user_username_exist:
                            return JsonResponse({'res': 0, 'message': texts.USERNAME_ALREADY_USED})

                        user_username_failure = user_username_failure_validate(new_user_username)

                        if user_username_failure:
                            clue_message = None
                            if user_username_failure is 1:
                                clue_message = texts.USERNAME_UNAVAILABLE
                            elif user_username_failure is 2:
                                clue_message = texts.USERNAME_LENGTH_PROBLEM
                            elif user_username_failure is 3:
                                clue_message = texts.USERNAME_8_CANNOT_DIGITS
                            elif user_username_failure is 4:
                                clue_message = texts.USERNAME_BANNED
                            return JsonResponse({'res': 0, 'message': clue_message})

                        try:
                            with transaction.atomic():
                                user_username = request.user.userusername
                                user_username.username = new_user_username
                                user_username.save()
                        except Exception:
                            return JsonResponse({'res': 0, 'message': texts.UNEXPECTED_ERROR})

                        return JsonResponse({'res': 1, 'username': escape(new_user_username)})

                elif request.POST.get('command', None) == 'email':
                    new_user_primary_email = request.POST.get('email', None)
                    if new_user_primary_email is not None:

                        user_primary_email_exist = UserPrimaryEmail.objects.filter(email=new_user_primary_email).exists()
                        if user_primary_email_exist:
                            return JsonResponse({'res': 0, 'message': texts.EMAIL_ALREADY_USED})

                        user_primary_email_failure = user_primary_email_failure_validate(new_user_primary_email)
                        if user_primary_email_failure:
                            clue_message = None
                            if user_primary_email_failure is 1:
                                clue_message = texts.EMAIL_UNAVAILABLE
                            elif user_primary_email_failure is 2:
                                clue_message = texts.EMAIL_LENGTH_OVER_255
                            return JsonResponse({'res': 0, 'message': clue_message})

                        try:
                            with transaction.atomic():

                                checker_while_loop = 0
                                counter_if_loop = 0
                                uid = urlsafe_base64_encode(force_bytes(request.user.pk)).decode()
                                token = account_activation_token.make_token(request.user)
                                while checker_while_loop is 0:
                                    if counter_if_loop <= 9:

                                        try:
                                            UserPrimaryEmailAuthToken.objects.create(
                                                user_primary_email=request.user.userprimaryemail,
                                                uid=uid,
                                                token=token,
                                                email=new_user_primary_email,
                                            )
                                        except IntegrityError as e:
                                            if 'UNIQUE constraint' in str(e.args):
                                                counter_if_loop = counter_if_loop + 1
                                            else:
                                                return JsonResponse({'res': 0, 'message': texts.EMAIL_CONFIRMATION_EXTRA_ERROR})
                                    checker_while_loop = 1

                                subject = '[' + texts.SITE_NAME + ']' + texts.EMAIL_CONFIRMATION_SUBJECT

                                message = render_to_string('authapp/_account_activation_email.html', {
                                    'username': request.user.userusername.username,
                                    'name': request.user.usertextname.name,
                                    'email': new_user_primary_email,
                                    'domain': texts.SITE_DOMAIN,
                                    'site_name': texts.SITE_NAME,
                                    'uid': uid,
                                    'token': token,
                                })

                                new_user_email_list = [new_user_primary_email]

                                send_mail(
                                    subject=subject, message=message, from_email=options.DEFAULT_FROM_EMAIL,
                                    recipient_list=new_user_email_list
                                )
                                # End Transaction
                        except Exception:
                            return JsonResponse({'res': 0, 'message': texts.UNEXPECTED_ERROR})

                        return JsonResponse({'res': 1, 'email': texts.EMAIL_SENT + ': ' + new_user_primary_email})
        return JsonResponse({'res': 2})


@ensure_csrf_cookie
def username_change(request):
    if request.method == "POST":
        if request.is_ajax():
            if request.POST['username']:
                try:
                    with transaction.atomic():
                        new_username = request.POST['username']
                        new_username = new_username.lower()
                        exist_user_username = UserUsername.objects.filter(username=new_username).exists()
                        if exist_user_username is not None:
                            return clue_json_response(0, texts.USERNAME_ALREADY_USED)

                        username_failure = user_username_failure_validate(new_username)

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
