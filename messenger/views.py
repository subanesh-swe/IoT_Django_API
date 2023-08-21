from datetime import datetime
from http.client import HTTPResponse
from pyexpat import model
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.core import serializers
from . import models
import json

#@login_required
def indexView(request):
    return render(
        request,
        'messenger/socketTest.html'
    )
    #return redirect('rooms')
    #return render(
    #    request,
    #    'messenger/map.html'
    #)
    #"""Renders the index page."""
    #return render(
    #    request,
    #    'messenger/index.html',
    #    {
    #        'title':'Messenger Home Page',
    #        'message':'Connect the Universe',
    #        'year':datetime.now().year,
    #    }
    #)



def roomsView(request):
    if request.method == 'POST':
        try :
            currUser    = request.user
            formTitleSender = request.POST.get('formTitleSender')
            roomNameOrId    = request.POST.get('roomNameOrId')
            enabelPassword  = request.POST.get('enabelPassword')
            currPassword    = request.POST.get('password')
            result          = {'result':False, 'alert': 'Invalid Request'}
            if enabelPassword is None :
                currPassword = "None"
            
            if formTitleSender == "Create new Room":
                currRoomName = roomNameOrId
                result = models.Room.createRoom(currUser=currUser , currRoomName=currRoomName, currPassword=currPassword)
            elif formTitleSender == "Join new Room":
                currRoomId = roomNameOrId
                result = models.Room.joinRoom(currUser=currUser, currRoomId=currRoomId, currPassword=currPassword)

            return JsonResponse(result)
        except Exception as err :
            return JsonResponse({'result':False, 'alert':'Something went wrong!!! Please Refresh the page and try again. if the problem continues feel free to contact customer support!'  })

    else:
        currUser = request.user
        currRoomList = models.Room.getUserRoomsList(currUser)
        ###print("currRoomList:",currRoomList)
        roomListLabel = 'List of rooms you have joined'
        if not currRoomList :
            roomListLabel = "You haven't joined any rooms yet. Please create a new room or join a room"

        context = {
            'roomListLabel': roomListLabel,
            'roomList': currRoomList,
        }
    
        return render(request, 'messenger/rooms.html', context)



def chatView(request, slug):
    #return HTTPResponse(f"requested room : {slug}")
    #currRoomDetails = models.getUserRoomCustomDetail(slug)
    currRoomDetails = models.Room.getById(slug).customDict()
    currRoomDetails['userName'] = str(request.user.username)
    currRoomDetails['userId'] = str(request.user.userid)
    #print("currRoomDetails:",currRoomDetails)
    #if currRoomDetails.get("createdAt") :
    #    currRoomDetails["createdAt"] = str(currRoomDetails.get("createdAt"));
    #if currRoomDetails.get("updatedAt") :
    #    currRoomDetails["updatedAt"] = str(currRoomDetails.get("updatedAt"));
    #print("str",str(currRoomDetails.get("createdAt")))
    #print("str",str(currRoomDetails.get("updatedAt")))
    content = {
        'title': 'Chat',
        'userName': request.user.username,
        'userId': request.user.userid,
        'roomName': currRoomDetails['roomName'],
        'roomId': currRoomDetails['roomId'],
        'roomData': currRoomDetails,
    }
    return render(request, 'messenger/chat.html', content)

    #currRoomDetails = models.get_user_room(slug)
    #print("currRoomJson:",currRoomJson)
    #if currRoomDetails:
    #    currRoomJson = serializers.serialize('json',currRoomDetails)
    #    print("currRoomJson:",currRoomJson)
    #    return render(
    #        request,
    #        'messenger/index.html',
    #        {
    #            'title':'Messenger Home Page',
    #            'message':str(currRoomDetails),
    #            'year':datetime.now().year,
    #        }
    #    )
    #return render(request, 'messenger/chat.html')
    #else:
        #redirect('rooms')
