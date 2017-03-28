"""fullauthsystem URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url,include
from django.contrib import admin
from accounts import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^accounts/',include('accounts.urls')),
    url(r"^accounts/", include("django.contrib.auth.urls")),
    url(r"^password_change/done/$", auth_views.password_change_done, name="password_change_done"),


url(r'^password_reset/$', auth_views.password_reset, name='password_reset'),
    url(r'^password_reset/done/$', auth_views.password_reset_done, name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.password_reset_confirm, name='password_reset_confirm'),
    url(r'^reset/done/$', auth_views.password_reset_complete, name='password_reset_complete'),




    url(r'^$', views.Homepage.as_view(), name="home"),
    url(r'^notallwoed/$', views.ErrorView.as_view(), name="error"),
    url(r'^dados/update/$', views.updatedata.as_view(), name="update"),



url(r'^resetform', views.resetpassword, name='reset_password'),





    url(r'^usuarios-autocomplete/$',
        views.UsuarioAutocomplete.as_view(),
        name='usuarios-autocomplete',
    ),

]
