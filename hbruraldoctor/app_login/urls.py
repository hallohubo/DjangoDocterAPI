from django.urls import path

from .views import validatePort, registerPort, publishKey
from django.views.decorators.csrf import csrf_exempt




# app_name will help us do a reverse look-up latter.
urlpatterns = [
    path('validate', validatePort),
    path('regist', registerPort),
    path('pubKey', publishKey),
]