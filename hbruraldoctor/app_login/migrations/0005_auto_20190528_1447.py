# Generated by Django 2.2.1 on 2019-05-28 06:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app_login', '0004_auto_20190528_1410'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='usermodel',
            name='hadPast',
        ),
        migrations.RemoveField(
            model_name='usermodel',
            name='imei',
        ),
        migrations.RemoveField(
            model_name='usermodel',
            name='key',
        ),
        migrations.RemoveField(
            model_name='usermodel',
            name='seed',
        ),
        migrations.RemoveField(
            model_name='usermodel',
            name='sign',
        ),
        migrations.RemoveField(
            model_name='usermodel',
            name='source',
        ),
        migrations.RemoveField(
            model_name='usermodel',
            name='ver',
        ),
        migrations.AddField(
            model_name='usermodel',
            name='user_gender',
            field=models.CharField(max_length=10, null=True, verbose_name='性别'),
        ),
        migrations.AddField(
            model_name='usermodel',
            name='user_phone',
            field=models.CharField(max_length=15, null=True, verbose_name='手机号'),
        ),
    ]