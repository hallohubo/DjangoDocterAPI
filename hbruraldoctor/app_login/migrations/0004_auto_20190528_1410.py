# Generated by Django 2.2.1 on 2019-05-28 06:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app_login', '0003_usermodel'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='usermodel',
            options={'verbose_name': '用户名', 'verbose_name_plural': '用户名'},
        ),
        migrations.AddField(
            model_name='usermodel',
            name='hadPast',
            field=models.CharField(default=False, max_length=10),
        ),
        migrations.AddField(
            model_name='usermodel',
            name='imei',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='usermodel',
            name='key',
            field=models.CharField(max_length=30, null=True),
        ),
        migrations.AddField(
            model_name='usermodel',
            name='seed',
            field=models.CharField(max_length=65, null=True),
        ),
        migrations.AddField(
            model_name='usermodel',
            name='sign',
            field=models.CharField(max_length=65, null=True),
        ),
        migrations.AddField(
            model_name='usermodel',
            name='source',
            field=models.CharField(max_length=10, null=True),
        ),
        migrations.AddField(
            model_name='usermodel',
            name='ver',
            field=models.CharField(max_length=25, null=True),
        ),
        migrations.AlterField(
            model_name='usermodel',
            name='nick_name',
            field=models.CharField(max_length=20, null=True, verbose_name='昵称'),
        ),
        migrations.AlterField(
            model_name='usermodel',
            name='user_address',
            field=models.CharField(max_length=35, null=True, verbose_name='住址'),
        ),
    ]
