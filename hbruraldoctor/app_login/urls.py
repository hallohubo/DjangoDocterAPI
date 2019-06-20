from django.urls import path

from .views import validatePort, registerUser, publishKey, decryptPassword, loginAccount
from django.views.decorators.csrf import csrf_exempt




# app_name will help us do a reverse look-up latter.
urlpatterns = [
    path('validate', validatePort),
    path('register', registerUser),
    path('pubKey', publishKey),
    path('getPassword', decryptPassword),
    path('login', loginAccount),
]