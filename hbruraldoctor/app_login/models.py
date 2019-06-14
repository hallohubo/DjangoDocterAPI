from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# Create your models here.
class ValidatePost(models.Model):
    version = models.CharField(max_length=25)
    imei = models.CharField(max_length=50)
    source = models.CharField(max_length=10)
    sign = models.CharField(max_length=65)
    key = models.CharField(max_length=30)
    date = models.DateTimeField(editable=False, auto_now_add=True)
    seed = models.CharField(max_length=65)
    secondSeed = models.CharField(max_length=65)

    class Meta:
        # db_table = 'user_table'
        verbose_name = '用户请求日志'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.imei

class UserModel(AbstractUser):
    #  AbstractUser这个类，也就是Django框架默认使用的一个用于管理用户的User类，这个类生成一个auth_user表。所以，要扩展用户属性，可以继承AbstractUser，在子类UserModel中实现扩展。
    nick_name = models.CharField(max_length=20, verbose_name='昵称', null=True)
    user_address = models.CharField(max_length=35, verbose_name='住址', null=True)
    user_gender = models.CharField(max_length=10, verbose_name="性别", null=True)
    user_phone = models.CharField(max_length=15, verbose_name='手机号', null=True)
    user_idcard = models.CharField(max_length=50, verbose_name='身份证号', null=True)


    class Meta:
        # 配置自定义用户表名是user_table
        db_table = 'user_table'
        verbose_name = '用户名'
        verbose_name_plural = verbose_name

