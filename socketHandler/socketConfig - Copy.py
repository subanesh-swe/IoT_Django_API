 set async_mode to 'threading', 'eventlet', 'gevent' or 'gevent_uwsgi' to
 force a mode else, the best mode is selected automatically from what's
 installed

import os

from django.http import HttpResponse
import socketio

from messenger.models import Room
from asgiref.sync import sync_to_async

async_mode = 'gevent';
sio     = socketio.Server(async_mode=async_mode);



##@sio.event
##def connect(sid, environ):
##	try :
##		UserId = environ['QUERY_STRING'].split('=')[1].split('&')[0] #.replace("-","")
##		sio.enter_room(sid, "subanesh")
##		print(f"Socket ---> Connected <---   UserId: {UserId}, SocketId: {sid}, Query:{environ['QUERY_STRING']}");

##		sendData = {
##			'userId': "3857530f-7012-448b-a37b-b8d713661b2b",
##			'roomId': "7044fdd5244d4cbb",
##			'data': {
##				'message': 'overriding join room',
##				'sender': 'tester',
##			}
##		}
##		sio.emit("receiveMessage",sendData )
##	except Exception as err :
##		print(f"Error @sendMessage: {err}")


##@sio.event
##def disconnect(sid):
##	try :
##		print(f"Socket --> Disconnected <--  SocketId: ${sid}")
##	except Exception as err :
##		print(f"Error @sendMessage: {err}")

##@sio.on('sendMessage')
##def sendMessage(sid, receivedData):
##	try :
##		roomId = receivedData.get('roomId')
##		recipientIds = Room.getUserIdsByRoomId(roomId=roomId)
##		print(f"recipientIds: {recipientIds}")
##		for recipientId in recipientIds:
##			print(f"Sendimg msg to id: { recipientId }")
##			#sio.enter_room(sid, recipientId)
##			sio.emit('receiveMessage', receivedData , room="subanesh")
##			#sio.leave_room(sid, recipientId)
##	except Exception as err :
##		print(f"Error @sendMessage: {err}")








# thread = None
users = {};

# def background_thread():
#     """ Exemple de programme d'execution de programme d'arriere plan """

#     count = 0;

#     while True:
#         sio.sleep(10);
#         count += 1;
#         sio.emit('my_response', {'data': 'Server generated event'}, namespace='/test');

@sio.event
def set_username(sid, message):
    """ Programme de modification du nom d'utilisateur """
    users[sid] = message['data'];

    # on notifit que le username a ete correctement notifie
    sio.emit('my_response', {'data': f"Username is set to {users[sid]} !"}, to=sid);



@sio.event
def my_event(sid, message):
    # Programme qui permet d'envoyer le message a moi meme
    sio.emit('my_response', {'data': message['data']}, room=sid);



@sio.event
def my_broadcast_event(sid, message):
    # Programme qui permet d'envoyer le message a tous le monde
    sio.emit('my_response', {'data': f"[{users[sid]}] {message['data']}"});



@sio.event
def join(sid, message):
    """ Programme de creation et d'adesion de canale """

    # on cree le canale et on se join a ce canal
    sio.enter_room(sid, message['room']);

    # sio.emit('my_response', {'data': 'Entered room: ' + message['room']}, room=sid);

    # on emet a tous ceux qui sont dans le canal qu'on de 
    # rejoindre le canal
    sio.emit('my_response', {'data': 'Entered room: ' + message['room']}, to=message['room']);


@sio.event
def leave(sid, message):
    """ Programme de deconnection d'un canal """

    # on se deconnecte du canal
    sio.leave_room(sid, message['room']);

    # on informe tous ceux qui sont dans le canal, que celui-ci 
    # a quitte le canal
    sio.emit('my_response', {'data': users[sid] + ' left room: ' + message['room']}, room=message['room']);


@sio.event
def close_room(sid, message):
    """ Programme de fermeture d'un canal """

    # on ferme le canal
    sio.close_room(message['room']);
    sio.emit('my_response', {'data': 'Room ' + message['room'] + ' is closing.'}, room=message['room']);


@sio.event
def my_room_event(sid, message):
    """ Programme qui permet d'envoyer un message a tous les membres du canal """
    sio.emit('my_response', {'data': f"[{users[sid]}] {message['data']}"}, room=message['room']);


@sio.event
def disconnect_request(sid):
    """ Programme qui declanche la deconnection de l'utilisateur """
    sio.disconnect(sid);


@sio.event
def connect(sid, environ):
    """ Programme de connexion 
        Au cour de la connexion, on enregistre tous les utilisateurs 
        connectes
    """

    print(f"{sid}\t connected");

    # on ajoute le nouveau a la liste
    users[sid] = None;

    # on lui notifie qu'il s'est bien connecte
    sio.emit('my_response', {'data': 'Connected', 'count': len(users)}, room=sid);

    # on notifie a tous le monde le nombre de personnes actuellement connectes
    sio.emit('my_response', {'data': f'{len(users)} connected now!', 'count': len(users)});


@sio.event
def disconnect(sid):
    """ Programme de deconnexion
        Lors de la deconnexion, on supprime l'utilisateur de la liste des
        connectes
    """

    print(f"{sid}\t {users[sid]} disconnected");

    # on notifie a tous le monde le nombre de personnes actuellement connectes
    sio.emit('my_response', {'data': f"{users[sid]} is disconnected", 'count': len(users)});

    # on le supprime de la liste 
    del users[sid];

    # on notifie a tous le monde le nombre de personnes actuellement connectes
    sio.emit('my_response', {'data': f'{len(users)} connected', 'count': len(users)});


