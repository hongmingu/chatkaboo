from django.urls import path, re_path
from authapp import views

app_name = 'authapp'

urlpatterns = [
    #
    # re_path(r'^$', views.accounts, name='accounts'),
    #
    # re_path(r'^email/key/send/$', views.email_key_send, name='email_key_send'),
    re_path(r'^email/key/confirm/(?P<uid>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
            views.primary_email_key_confirm, name='primary_email_key_confirm'),
    #
    # re_path(r'^logout/$', views.log_out, name='log_out'),
    #
    # re_path(r'^username/change/$', views.username_change, name='username_change'),
    #
    # re_path(r'^password/change/$', views.password_change, name='password_change'),
    # re_path(r'^password/reset/$', views.password_reset, name='password_reset'),
    #
    # re_path(r'^email/add/$', views.email_add, name='email_add'),
]
'''
    url(r'^create/$', views.main_create_log_in, name='create'),
'''