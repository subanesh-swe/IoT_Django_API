import os

import socketio
from asgiref.sync import sync_to_async
import json

from messenger.models import Room

asyncMode = 'asgi'
sio = socketio.AsyncServer(async_mode=asyncMode)
## To help you debug issues, the server can be configured to output logs to the terminal
#sio = socketio.AsyncServer(async_mode='asgi', logger=True, engineio_logger=True)

app = socketio.ASGIApp(sio)

@sio.on('subscribe')
async def subscribe(sid, receivedData):
	try :
		userId = receivedData.get('userId')
		sio.enter_room(sid, userId)
		### save session to access the data with all sio functions
		await sio.save_session(sid, {'userId': userId})
		#### to access the session
		#session = await sio.get_session(sid)
		#userId = session.get('userId')
		print(f"Socket ---> Subscribed <---   UserId: {userId}, SocketId: {sid}, receivedData:{receivedData}");
		sendData = {
			'userId': "server-userid",
			'roomId': "server-room",
			'data': {
				'sender': 'server',
				'message': 'you are subscribed to server',
			}
		}
		await sio.emit("receiveMessage",sendData)
	except Exception as err :
		print(f"Error @disconnect: {err}")


@sio.on('unsubscribe')
async def unsubscribe(sid, receivedData):
	try :
		userId = receivedData.get('userId')
		#### to access the session
		#session = await sio.get_session(sid)
		#userId = session.get('userId')
		sio.leave_room(sid, userId)
		print(f"Socket ---> unSubscribed <---   UserId: {userId}, SocketId: {sid}, receivedData:{receivedData}");
	except Exception as err :
		print(f"Error @disconnect: {err}")


@sio.on('sendMessage')
async def sendMessage(sid, receivedData):
	try :
		### to access the session
		session = await sio.get_session(sid)
		print("---")
		userId = session.get('userId')
		print(f"socket --> receiced -> userId: {userId}, receivedData: {receivedData}")
		if userId:
			roomId = receivedData.get('roomId')
			recipientIds = await sync_to_async(Room.getUserIdsByRoomId)(roomId=roomId)
			print(f"recipientIds: {recipientIds}")
			for recipientId in recipientIds:
				print(f"Sendimg msg to id: { recipientId }")
				#sio.enter_room(sid, recipientId)
				await sio.emit('receiveMessage', receivedData , room=recipientId)
				#sio.leave_room(sid, recipientId)
	except Exception as err :
		print(f"Error @sendMessage: {err}")


@sio.event
async def connect(sid, environ):
	try :
		#queryJson = json.dumps(dict(pair.split('=') for pair in environ['QUERY_STRING'].split('&')))
		queryDict = dict(pair.split('=') for pair in environ['QUERY_STRING'].split('&'))
		userId = queryDict.get('userId')
		if userId :
			sio.enter_room(sid, userId)
			### save session to access the data with all sio functions
			await sio.save_session(sid, {'userId': userId})
			#### to access the session
			#session = await sio.get_session(sid)
			#print('message from ', session['userId'])
			print(f"Socket ---> Connected <--- userId:{userId}, SocketId: {sid}, Query:{environ['QUERY_STRING']}");
			sendData = {
				'userId': "server-userid",
				'roomId': "server-room",
				'data': {
					'sender': 'server',
					'message': 'you are connected to server',
				}
			}
			await sio.emit("receiveMessage",sendData )
	except Exception as err :
		print(f"Error @connect: {err}")

@sio.event
async def disconnect(sid):
	try :
		### to access the session
		session = await sio.get_session(sid)
		userId = session.get('userId')
		sio.leave_room(sid, userId)
		print(f"Socket ---> Disconnected <--- userId:{userId}, SocketId: {sid}");
	except Exception as err :
		print(f"Error @disconnect: {err}")


#@sio.event
#def connect(sid, environ):
#	try :
#		UserId = environ['QUERY_STRING'].split('=')[1].split('&')[0] #.replace("-","")
#		sio.enter_room(sid, "subanesh")
#		print(f"Socket ---> Connected <---   UserId: {UserId}, SocketId: {sid}, Query:{environ['QUERY_STRING']}");

#		sendData = {
#			'userId': "3857530f-7012-448b-a37b-b8d713661b2b",
#			'roomId': "7044fdd5244d4cbb",
#			'data': {
#				'message': 'overriding join room',
#				'sender': 'tester',
#			}
#		}
#		sio.emit("receiveMessage",sendData )
#	except Exception as err :
#		print(f"Error @sendMessage: {err}")


#@sio.event
#def disconnect(sid):
#	try :
#		print(f"Socket --> Disconnected <--  SocketId: ${sid}")
#	except Exception as err :
#		print(f"Error @sendMessage: {err}")

#@sio.on('sendMessage')
#def sendMessage(sid, receivedData):
#	try :
#		roomId = receivedData.get('roomId')
#		recipientIds = Room.getUserIdsByRoomId(roomId=roomId)
#		print(f"recipientIds: {recipientIds}")
#		for recipientId in recipientIds:
#			print(f"Sendimg msg to id: { recipientId }")
#			#sio.enter_room(sid, recipientId)
#			sio.emit('receiveMessage', receivedData , room="subanesh")
#			#sio.leave_room(sid, recipientId)
#	except Exception as err :
#		print(f"Error @sendMessage: {err}")








## thread = None
#users = {};

## def background_thread():
##     """ Exemple de programme d'execution de programme d'arriere plan """

##     count = 0;

##     while True:
##         sio.sleep(10);
##         count += 1;
##         sio.emit('my_response', {'data': 'Server generated event'}, namespace='/test');

#@sio.event
#def set_username(sid, message):
#    """ Programme de modification du nom d'utilisateur """
#    users[sid] = message['data'];

#    # on notifit que le username a ete correctement notifie
#    sio.emit('my_response', {'data': f"Username is set to {users[sid]} !"}, to=sid);



#@sio.event
#def my_event(sid, message):
#    # Programme qui permet d'envoyer le message a moi meme
#    sio.emit('my_response', {'data': message['data']}, room=sid);



#@sio.event
#def my_broadcast_event(sid, message):
#    # Programme qui permet d'envoyer le message a tous le monde
#    sio.emit('my_response', {'data': f"[{users[sid]}] {message['data']}"});



#@sio.event
#def join(sid, message):
#    """ Programme de creation et d'adesion de canale """

#    # on cree le canale et on se join a ce canal
#    sio.enter_room(sid, message['room']);

#    # sio.emit('my_response', {'data': 'Entered room: ' + message['room']}, room=sid);

#    # on emet a tous ceux qui sont dans le canal qu'on de 
#    # rejoindre le canal
#    sio.emit('my_response', {'data': 'Entered room: ' + message['room']}, to=message['room']);


#@sio.event
#def leave(sid, message):
#    """ Programme de deconnection d'un canal """

#    # on se deconnecte du canal
#    sio.leave_room(sid, message['room']);

#    # on informe tous ceux qui sont dans le canal, que celui-ci 
#    # a quitte le canal
#    sio.emit('my_response', {'data': users[sid] + ' left room: ' + message['room']}, room=message['room']);


#@sio.event
#def close_room(sid, message):
#    """ Programme de fermeture d'un canal """

#    # on ferme le canal
#    sio.close_room(message['room']);
#    sio.emit('my_response', {'data': 'Room ' + message['room'] + ' is closing.'}, room=message['room']);


#@sio.event
#def my_room_event(sid, message):
#    """ Programme qui permet d'envoyer un message a tous les membres du canal """
#    sio.emit('my_response', {'data': f"[{users[sid]}] {message['data']}"}, room=message['room']);


#@sio.event
#def disconnect_request(sid):
#    """ Programme qui declanche la deconnection de l'utilisateur """
#    sio.disconnect(sid);


#@sio.event
#def connect(sid, environ):
#    """ Programme de connexion 
#        Au cour de la connexion, on enregistre tous les utilisateurs 
#        connectes
#    """

#    print(f"{sid}\t connected");

#    # on ajoute le nouveau a la liste
#    users[sid] = None;

#    # on lui notifie qu'il s'est bien connecte
#    sio.emit('my_response', {'data': 'Connected', 'count': len(users)}, room=sid);

#    # on notifie a tous le monde le nombre de personnes actuellement connectes
#    sio.emit('my_response', {'data': f'{len(users)} connected now!', 'count': len(users)});


#@sio.event
#def disconnect(sid):
#    """ Programme de deconnexion
#        Lors de la deconnexion, on supprime l'utilisateur de la liste des
#        connectes
#    """

#    print(f"{sid}\t {users[sid]} disconnected");

#    # on notifie a tous le monde le nombre de personnes actuellement connectes
#    sio.emit('my_response', {'data': f"{users[sid]} is disconnected", 'count': len(users)});

#    # on le supprime de la liste 
#    del users[sid];

#    # on notifie a tous le monde le nombre de personnes actuellement connectes
#    sio.emit('my_response', {'data': f'{len(users)} connected', 'count': len(users)});


