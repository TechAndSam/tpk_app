from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager 

# Create your models here.
class UserType(models.Model):
	PUBLIC = 'PUBLIC'
	ADMIN = 'ADMIN'
	TYPE_CHOICES = (
			(PUBLIC, 'Public User'),
			(ADMIN, 'Admin User')
		) 
	type = models.CharField(max_length=10, choices=TYPE_CHOICES, default=PUBLIC)

	def __str__(self):
		return self.get_type_display()


class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        user_type = UserType.objects.get_or_create(type=UserType.ADMIN)[0]

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(username, email, password, user_type=user_type, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
	USER_TYPE_CHOICES = (
        ('PUBLIC', 'Public User'),
        ('ADMIN', 'Admin User'),
    )

	username = models.CharField(max_length=255, unique=True)
	email = models.EmailField(unique=True)
	password = models.CharField(max_length=128)
	code = models.CharField(max_length=10, default=None, null=True)
	is_verified = models.BooleanField(default=False)
	is_active = models.BooleanField(default=True)
	is_staff = models.BooleanField(default=False) 
	is_superuser = models.BooleanField(default=False)
	#user_type = models.ForeignKey(UserType, on_delete=models.CASCADE)
	user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='PUBLIC')

	USERNAME_FIELD = 'username'
	REQUIRED_FIELDS = ['email']

	objects = CustomUserManager()

	def __str__(self):
		return self.username


class UniqueRegistrationCode(models.Model):
	code = models.CharField(max_length=255, unique=True)
	used = models.BooleanField(default=False)
	status = models.CharField(max_length=20, choices=[('AVAILABLE', 'Available'), ('USED', 'Used')], default='AVAILABLE')

	def __str__(self):
		return self.code
		

