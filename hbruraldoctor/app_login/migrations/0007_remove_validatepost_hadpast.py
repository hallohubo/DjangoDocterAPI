# Generated by Django 2.2.1 on 2019-05-30 01:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app_login', '0006_usermodel_user_idcard'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='validatepost',
            name='hadPast',
        ),
    ]