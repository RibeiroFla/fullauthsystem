from django.contrib import admin
from django.contrib.auth.forms import ReadOnlyPasswordHashField

from .models import Usuario, Aluno, Professor
from .forms import UserChangeForm, UserCreationForm, Usuario, AlunoForm,\
    ProfessorForm

# Register your models here.

class ProjectAdmin(admin.ModelAdmin):

    def get_form(self, request, obj=None, **kwargs):
        # Proper kwargs are form, fields, exclude, formfield_callback
        if obj:
            self.form = UserChangeForm
        else:
            self.form = UserCreationForm
        return super(ProjectAdmin, self).get_form(request, obj, **kwargs)



class AlunoAdmin(admin.ModelAdmin):
    form = AlunoForm

class ProfessorAdmin(admin.ModelAdmin):
    form = ProfessorForm


admin.site.register(Usuario, ProjectAdmin)
admin.site.register(Professor, ProfessorAdmin)
admin.site.register(Aluno, AlunoAdmin)

