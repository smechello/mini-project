from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class Details(models.Model):
    otp=models.DecimalField(max_digits=6, decimal_places=0)
    generated_date=models.DateTimeField(auto_now=True)
    user=models.ForeignKey(User, on_delete=models.CASCADE)
    
class alert(models.Model):
    message=models.TextField()
    raise_by=models.ForeignKey(User,on_delete=models.CASCADE)
    created_at=models.DateTimeField(auto_now=True)
    