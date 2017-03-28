from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin
)
from django.db import models
from django.utils import timezone
from django.conf import settings


class UserManager(BaseUserManager):
    def create_user(self, email, Nome, User, password=None):


        user = self.model(
            email=self.normalize_email(email),
            Nome=Nome,
            User=User,
            password=password
        )
        user.set_password(password)
        user.save(using=self._db)
        return user


    def create_superuser(self, email,Nome, User, password):
        user = self.create_user(
            email,
            Nome,
            User,
            password
        )
        user.is_staff = True
        user.is_superuser = True
        user.save()
        return user



class Usuario(AbstractBaseUser,PermissionsMixin):
    Nome = models.CharField('Nome Completo',max_length=100)
    User = models.CharField('Usuario',max_length=20, unique=True)
    email = models.EmailField('Email',unique=True)
    Data_Associacao = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField('Ativo',default=True)
    is_staff = models.BooleanField(default=False)
    Professor = models.BooleanField(default=False)
    Aluno = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["Nome", "User"]
    objects = UserManager()

    def __str__(self):
        return self.User

    def get_short_name(self):
        return self.User

class Professor(models.Model):
    Matricula = models.AutoField(primary_key=True, max_length=10)
    Usuario = models.OneToOneField(settings.AUTH_USER_MODEL)
    Data_Nascimento = models.DateTimeField('Data de Nascimento')
    Endereco = models.TextField(max_length=200)
    Instituicao = models.CharField('Instituição de Ensino', max_length=80)


class Aluno(models.Model):
    Matricula = models.AutoField(primary_key=True, max_length=10)
    Usuario = models.OneToOneField(settings.AUTH_USER_MODEL)
    Data_Nascimento = models.DateTimeField('Data de Nascimento')
    Endereco = models.TextField(max_length=200)
    Instituicao = models.CharField('Instituição de Ensino', max_length=80)