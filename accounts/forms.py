from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth import password_validation
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm,SetPasswordForm, PasswordResetForm
from django.contrib.auth.forms import AuthenticationForm
from .models import Usuario, Professor, Aluno
from dal import autocomplete
from django import forms


class UserCreateForm(UserCreationForm):
    class Meta:
        fields = ("User","email", "password1","password2")
        model = get_user_model()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["User"].label = "Usuário"
        self.fields["email"].label = "Email"
        self.fields["password2"].help_text = None
        #self.fields["email"].widget.attrs['readonly']=True

    def clean_email(self):

        email = self.cleaned_data['email'].lower()
        try:
            u = Usuario.objects.get(email=email)
        except Usuario.DoesNotExist:
            return email
        raise forms.ValidationError('Email já em uso')
    # return self.cleaned_data['email'].lower()




class ChangePassword(PasswordChangeForm):
    class Meta:
        fields = ("new_password1", "new_password2", "old_password")
        model = get_user_model()


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["old_password"].help_text = None
        self.fields["new_password1"].help_text = None
        self.fields["new_password2"].help_text = None


class ResetPassword(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["new_password1"].help_text = None





class UserChangeForm(forms.ModelForm):

    class Meta:
        model = Usuario
        fields = ('email', 'Nome','is_staff','is_superuser','Professor',
                  'Aluno', 'Data_Associacao', 'last_login', 'is_active')


class UserCreationForm(forms.ModelForm):
    password1 = forms.CharField(label=("Senha"), widget=forms.PasswordInput)
    class Meta:
        model = Usuario
        fields = ('email','Nome', 'password1', 'is_staff','is_superuser','Professor',
                  'Aluno', 'Data_Associacao', 'last_login', 'is_active')



###### auto complete light#########

class ProfessorForm(forms.ModelForm):
    class Meta:
        model = Professor
        fields = ('__all__')
        widgets = {
            'Usuario': autocomplete.ModelSelect2(url='usuarios-autocomplete')
        }


class AlunoForm(forms.ModelForm):
    class Meta:
        model = Aluno
        fields = ('__all__')
        widgets = {
            'Usuario': autocomplete.ModelSelect2(url='usuarios-autocomplete')
        }