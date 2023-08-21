from datetime import datetime
from django.urls import path
from django.contrib.auth.views import LoginView, LogoutView
from . import views


urlpatterns = [
    path('', views.indexView, name='messenger'),
    path('rooms', views.roomsView, name='rooms'),
    path('rooms/<slug:slug>', views.chatView, name='chat'),
]
