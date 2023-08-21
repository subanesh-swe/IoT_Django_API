"""
WSGI config for IoT_Django_API project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/wsgi/
"""

import os
import socketio

from django.core.wsgi import get_wsgi_application
from django.contrib.staticfiles.handlers import StaticFilesHandler

from socketHandler.socketConfig import sio

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'IoT_Django_API.settings')
django_app = StaticFilesHandler(get_wsgi_application())
application = socketio.Middleware(sio, wsgi_app=django_app, socketio_path='socket.io')

#application = socketio.WSGIApp(sio, get_wsgi_application());

####################################################################################

from gevent import pywsgi
from geventwebsocket.handler import WebSocketHandler

server = pywsgi.WSGIServer(("", 8000), application, handler_class=WebSocketHandler);
server.serve_forever();