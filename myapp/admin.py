from django.contrib import admin
from .models import CustomUser, API, Tokens
# Register your models here.
admin.site.register(CustomUser)
admin.site.register(API)
admin.site.register(Tokens)
