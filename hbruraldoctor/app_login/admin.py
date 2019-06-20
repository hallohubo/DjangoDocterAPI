from django.contrib import admin
from .models import ValidatePost, UserModel

# Register your models here.
class ValidatePostAdmin(admin.ModelAdmin):
    list_display = ('id','imei', 'version', 'date', 'seed',)

# class UserAdmin(admin.ModelAdmin):
#     # 设置显示数据库中哪些字段
#     list_display = ['username', 'password', 'nickName', 'userAddress']
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'nickName', 'userGender', 'userPhone', 'is_active')
admin.site.register(ValidatePost, ValidatePostAdmin)
admin.site.register(UserModel, UserAdmin)


