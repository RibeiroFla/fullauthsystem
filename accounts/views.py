from django.contrib.auth import login, logout, authenticate,update_session_auth_hash, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.urlresolvers import reverse_lazy, reverse
from django.http import HttpResponseForbidden
from django.template.response import TemplateResponse
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.views import generic
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth.mixins import LoginRequiredMixin,UserPassesTestMixin
from django.shortcuts import render,redirect, HttpResponseRedirect, resolve_url
from dal import autocomplete
from . import forms
from . import models

class Homepage(generic.TemplateView):
    template_name = 'acc/home.html'

class LoginView(UserPassesTestMixin,generic.FormView):
    form_class = AuthenticationForm
    success_url = reverse_lazy("home")
    template_name = "acc/login.html"

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        return form_class(self.request, **self.get_form_kwargs())

    def form_valid(self, form):
        login(self.request, form.get_user())
        return super().form_valid(form)

    def test_func(self):
        return self.request.user.is_anonymous

    def handle_no_permission(self):
        return redirect('home')


class SignUp(UserPassesTestMixin,generic.CreateView):
    form_class = forms.UserCreateForm
    success_url = reverse_lazy("login")
    template_name = "acc/signup.html"

    def test_func(self):
        return self.request.user.is_anonymous

    def handle_no_permission(self):
        return redirect('home')


class LogoutView(generic.RedirectView):
    url = reverse_lazy("home")

    def get(self, request, *args, **kwargs):
        logout(request)
        return super().get(request, *args, **kwargs)


class EaeView(LoginRequiredMixin,UserPassesTestMixin, generic.TemplateView):
    template_name = 'acc/eae.html'

    def test_func(self):
        return self.request.user.is_staff

    def handle_no_permission(self):
        return HttpResponseForbidden()


class ErrorView(generic.TemplateView):
    template_name = "acc/notallowed.html"


class updatedataa(LoginRequiredMixin,generic.UpdateView):
    form_class = PasswordChangeForm
    template_name = 'acc/update.html'

    def get_success_url(self):
        return reverse('home', kwargs={})

    def get_object(self, queryset=None):
        obj = models.User.objects.get(id=self.request.user.id)
        return obj

    #def test_func(self):
        #print(self.request.user.pk)
        #print(self.kwargs['userid'])
        #print(self.request.user.pk == self.kwargs['userid'])
        #return self.request.user.pk == self.kwargs['userid']

    #def get_permission_denied_message(self):
        #return self.permission_denied_message




class updatedata(LoginRequiredMixin, generic.UpdateView):

    template_name = "registration/password_change_form.html"
    success_url = reverse_lazy('password_change_done')
    form_class = forms.ChangePassword

    def get_object(self, queryset=None):
        return self.request.user

    def get_form_kwargs(self):
        kwargs = super(updatedata, self).get_form_kwargs()
        kwargs['user'] = kwargs.pop('instance')

        return kwargs

class resetpassword(LoginRequiredMixin, generic.UpdateView):

    template_name = "registration/password_change_form.html"
    success_url = reverse_lazy('password_reset_complete')
    form_class = forms.ChangePassword

    def get_object(self, queryset=None):
        return self.request.user

    def get_form_kwargs(self):
        kwargs = super(resetpassword, self).get_form_kwargs()
        kwargs['user'] = kwargs.pop('instance')

        return kwargs

def password_reset_confirm(request, uidb64=None, token=None,
                           template_name='registration/password_reset_confirm.html',
                           token_generator=default_token_generator,
                           set_password_form=forms.ResetPassword,
                           post_reset_redirect=None,
                           current_app=None, extra_context=None):
    """
    View that checks the hash in a password reset link and presents a
    form for entering a new password.
    """
    UserModel = get_user_model()
    assert uidb64 is not None and token is not None  # checked by URLconf
    if post_reset_redirect is None:
        post_reset_redirect = reverse('password_reset_complete')
    else:
        post_reset_redirect = resolve_url(post_reset_redirect)
    try:
        # urlsafe_base64_decode() decodes to bytestring on Python 3
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = UserModel._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
        user = None

    if user is not None and token_generator.check_token(user, token):
        validlink = True
        title = ('Enter new password')
        if request.method == 'POST':
            form = set_password_form(user, request.POST)
            if form.is_valid():
                form.save()
                return HttpResponseRedirect(post_reset_redirect)
        else:
            form = set_password_form(user)
    else:
        validlink = False
        form = None
        title = ('Password reset unsuccessful')
    context = {
        'form': form,
        'title': title,
        'validlink': validlink,
    }
    if extra_context is not None:
        context.update(extra_context)

    if current_app is not None:
        request.current_app = current_app

    return TemplateResponse(request, template_name, context)


###################auto complete light################



class UsuarioAutocomplete(autocomplete.Select2QuerySetView):
    def get_queryset(self):
        # Don't forget to filter out results depending on the visitor !
        if not self.request.user.is_authenticated():
            return models.Usuario.objects.none()
        qs = models.Usuario.objects.all()

        if self.q:
            qs = qs.filter(User__istartswith=self.q)

        return qs
