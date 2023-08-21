from django.db import models
#from django.contrib.auth.models import User
from users.models import UserAccount as User
from django.contrib.auth.hashers import make_password as hashPassword, check_password as hashPasswordMatch
from django.utils import timezone
import uuid, random

def getRoom(currRoomId) :
    currRoom = None
    try:
        currRoom = Room.objects.get( pk = currRoomId )
    except Exception as err:
        print(f"Error captured @[getRoom] {err}")
        currRoom = None
    return currRoom

def getUniqueId():
    while True:
        letters = str(uuid.uuid4().hex) + str(uuid.uuid4().hex)
        uniqueId = ''.join(random.choice(letters) for _ in range(16))
        if not getRoom(currRoomId=uniqueId) :
            return uniqueId

class Profile(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    isAdmin     = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username

class Room(models.Model):
    roomId              = models.CharField(primary_key=True, default=getUniqueId(), max_length=36, unique=True, editable=False, verbose_name='ID', help_text='roomId')
    roomName            = models.CharField(default='', max_length=255,  blank=True, null=True, verbose_name='Name',         help_text='roomName')
    roomPassword        = models.CharField(default='', max_length=255,  blank=True, null=True, verbose_name='Password',     help_text='roomPassword')
    roomData            = models.JSONField(default=dict,                blank=True, null=True, verbose_name='Data',         help_text='roomData')
    createdAt           = models.DateTimeField(default = timezone.now,  blank=True, null=True, verbose_name='Created At',   help_text='createdAt')
    updatedAt           = models.DateTimeField(default = timezone.now,  blank=True, null=True, verbose_name='Updated At',   help_text='updatedAt')

    roomProfiles        = models.ManyToManyField(Profile)
    
    #def __str__(self):
    #    return self.roomId
    
    #def __customfields__(self):
    #    return { 'roomId': self.roomId, 'roomName': self.roomName, 'roomPassword': self.roomPassword,'roomProfiles': self.roomProfiles, 'createdAt': self.createdAt, 'updatedAt': self.updatedAt }
    
def getUserRoomsList(currUser) :
    userRoomsList = []
    try :
        for prf in currUser.profile_set.all() :
            for rm in prf.room_set.all() :
                #print(f"+++++++++++++{rm.__dict__}") will give all fields in rm
                userRoomsList.append( {'roomId': rm.roomId, 'roomName':rm.roomName, 'updatedAt':rm.updatedAt} )
    except Exception as err:
        print("captured error!!! @[Room.getUserRoomsList]")
    return userRoomsList

def createRoom(currUser, currRoomName, currPassword):
    currRoom = Room.objects.create(
        roomName        = currRoomName,
        roomPassword    = hashPassword(currPassword),
    )
    currProfile = Profile.objects.create(
        user        = currUser,
        isAdmin   = True,
    )
    currRoom.roomProfiles.add( currProfile )
    currRoom.save();

    return {
        'result': True,
        'redirect': f'/messenger/rooms/{currRoom.roomId}',
        'alert': f"New room '{currRoomName}' created with ID: '{currRoom.roomId}', Password: '{currPassword}'",
    }

def joinRoom(currUser, currRoomId, currPassword):
    currRoom = getRoom( currRoomId=currRoomId )
    
    if currRoom is None:
        return {
            'result': False,
            'redirect': f'/messenger/rooms',
            'alert': "Invalid Room Id, there is no such room exist!!!",
        }

    if not hashPasswordMatch(currPassword, currRoom.roomPassword):
        return {
            'result': False,
            'redirect': f'/messenger/rooms',
            'alert': "Invalid Password!!!",
        }
    currProfile = Profile.objects.create(
        user        = currUser, 
        isAdmin		= False,
    )
    currRoom.roomProfiles.add( currProfile )
    currRoom.save()

    return {
        'result': True,
        'redirect': f'/messenger/rooms/{currRoomId}',
        'alert': "Join successful!",
    }




#def getUserRoomsList(currUser) :
#    userRoomsList = []
#    try :
#        profiles = currUser.profile_set.all()
#        print(f"profiles: {profiles}")
#        profileRooms = [ pr.room_set.all() for pr in profiles ]
#        print(f"profileRooms: {profileRooms}")

#        userRoomsList = []
#        for room in profileRooms:
#            rm = room.values()[0]
#            print(f"rm: {rm}")
#            rmd = {'roomId': rm.get('roomId'], 'roomName':rm.get('roomName'), 'updatedAt':rm.get('updatedAt') }
#            print(f"Rmd: {rmd}")
#            userRoomsList.append(rmd)
#        #userRoomsList = [{'roomId': rm.roomId, 'roomName':rm.roomName } for room in profileRooms for rm in getRoom(room)]
#        print(f"userRoomsList: {userRoomsList}")
#    except Exception as err:
#        print("captured error!!! ___________________________")
#    return userRoomsList

#def getUserRoomCustomDetail(currRoomId) :
#    currRoom            = getRoom( currRoomId=currRoomId )
#    customReturnValue   = { 'roomId': currRoom.roomId, 'roomName': currRoom.roomName, 'roomPassword': currRoom.roomPassword,'roomProfiles': currRoom.roomProfiles, 'createdAt': currRoom.createdAt, 'updatedAt': currRoom.updatedAt }
#    return customReturnValue
