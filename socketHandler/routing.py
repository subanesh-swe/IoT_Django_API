# chat/routing.py

from django.urls import path
from . import socketConfig

socketio_urlpatterns = [
    #path(r'^socket.io/', socketConfig.app),
    path(r'socket.io/', socketConfig.app),
]

#from django.urls import path

#from . import socketConfig

#websocket_urlpatterns = [
#    path('ws/<str:room_name>/', socketConfig.app),
#]