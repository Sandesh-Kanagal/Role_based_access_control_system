from django.db import models
from datetime import datetime, timedelta
import jwt
from django.conf import settings
from django.contrib.auth.hashers import make_password

class CustomUser(models.Model):
    username=models.CharField(max_length=100,unique=True)
    password=models.CharField(max_length=100)
    role=models.CharField(max_length=10, choices=(("Admin","Admin"), ("User","User"), ("Viewer","Viewer")),default="User")

    def save(self, *args, **kwargs):
        if not self.id:  
            # Check if the instance is being created (no primary key exists)
            # Hash the password only when creating a new user
            self.password = make_password(self.password)
        else:
            # Check if the password field is being updated explicitly
            user = CustomUser.objects.get(pk=self.id)
            if user.password != self.password:
                # Hash the password only when the password field is updated
                self.password = make_password(self.password)

        super(CustomUser, self).save(*args, **kwargs)


class API(models.Model):
    creator= models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='created_apis')
    users = models.ManyToManyField(CustomUser, related_name='accessible_apis')
    name = models.CharField(max_length=100)
    desc = models.TextField()

    def can_update(self, user):
        return user == self.creator.user

    def __str__(self):
        return self.name 

    
class Tokens(models.Model):
    userid=models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token=models.TextField(null=True, blank=True)

    def generate_jwt_token(self):
        token_payload = {
            'user_id': self.pk,
            'exp': datetime.utcnow() + timedelta(days=1),         
            }
        return jwt.encode(token_payload, settings.SECRET_KEY, algorithm='HS256')
    def save_token(self):
        token = self.generate_jwt_token()
        # Save the token to the model's token field
        self.token = token 
        self.save()
