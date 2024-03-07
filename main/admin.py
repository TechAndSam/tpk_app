from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, UniqueRegistrationCode

# Register your models here.
# class CustomUserAdmin(UserAdmin):
#     list_display = ('username', 'email')

#     def refresh_token(self, obj):
#         return obj.refresh_token

#     def access_token(self, obj):
#         return obj.access_token 


admin.site.register(User)
#admin.site.register(User)
admin.site.register(UniqueRegistrationCode)
