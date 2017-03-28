from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^signup/$', views.SignUp.as_view(), name="signup"),
    url(r'^login/$', views.LoginView.as_view(), name="login"),
    url(r'^logout/$', views.LogoutView.as_view(),name="logout"),
    url(r'^eae/$', views.EaeView.as_view(), name="eae"),
]