from django.db import models
#from django.contrib.auth.models import User
from users.models import UserAccount as User
from django.contrib.auth.hashers import make_password as hashPassword, check_password as hashPasswordMatch
from asgiref.sync import sync_to_async
from django.utils import timezone
import uuid, random

class Profile(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    isAdmin     = models.BooleanField(default=False)

    def str(self):
        return self.user.username

class Room(models.Model):
    roomId              = models.CharField(primary_key=True, default= '', max_length=36, unique=True, editable=False, verbose_name='ID', help_text='roomId')
    roomName            = models.CharField(default='', max_length=255,  blank=True, null=True, verbose_name='Name',         help_text='roomName')
    roomPassword        = models.CharField(default='', max_length=255,  blank=True, null=True, verbose_name='Password',     help_text='roomPassword')
    roomData            = models.JSONField(default=dict,                blank=True, null=True, verbose_name='Data',         help_text='roomData')
    createdAt           = models.DateTimeField(default = timezone.now,  blank=True, null=True, verbose_name='Created At',   help_text='createdAt')
    updatedAt           = models.DateTimeField(default = timezone.now,  blank=True, null=True, verbose_name='Updated At',   help_text='updatedAt')

    roomProfiles        = models.ManyToManyField(Profile)
    
    def str(self):
        return self.roomId

    def customDict(self):
        data = super().__dict__
        data.pop('_state', None)
        data.pop('createdAt', None)
        data.pop('updatedAt', None)
        data.pop('roomPassword', None)
        #for key in data:
        #    if isinstance(data[key], int):
        #        continue
        #    data[key] = str(data[key])
        #print("__dict__",data)
        return data

    ###""" set uniqueId """###
    ###""" set uniqueId >> Setting default=getUniqueId() in the roomId field definition is similar to using the init method to set the roomId field when creating a new Room object but before it s saved to the database."""###
    def __init__(self, *args, **kwargs):
        print("init room -------------")
        super(Room, self).__init__(*args, **kwargs)
        if not self.roomId:
            self.roomId = self.getUniqueId()
            print("init room ------------- UUid generated ->", self.roomId)

    ###""" get uniqueId """###
    @staticmethod
    def getUniqueId():
        while True:
            print("creating roomId")
            letters = str(uuid.uuid4().hex) + str(uuid.uuid4().hex)
            uniqueId = ''.join(random.choice(letters) for _ in range(16))
            if not Room.getById(uniqueId):
                return uniqueId

    @staticmethod
    def getById(getRoomId):
        currRoom = None
        try:
            currRoom = Room.objects.get(pk=getRoomId)
        except Exception as err:
            print(f"Error captured @[Room.getById] {err}")
            currRoom = None
        return currRoom
    
            

    @staticmethod
    def getUserRoomsList(currUser) :
        userRoomsList = []
        try :
            ### here everything will be Object
            for prf in currUser.profile_set.all() :
                for rm in prf.room_set.all() :
                    userRoomsList.append( {'roomId': rm.roomId, 'roomName':rm.roomName, 'updatedAt':rm.updatedAt} )
                    ###(rm.dict) will give all fields in rm as dict
                    ###roomData=rm.dict
                    ###print(f"roomData: {roomData}")
                    ###userRoomsList.append( {'roomId': roomData['roomId'], 'roomName':roomData.get('roomName'), 'updatedAt':roomData.get('updatedAt') } )
        except Exception as err:
            print("captured error!!! @[Room.getUserRoomsList]")
        return userRoomsList

    #@classmethod
    #def getUserIdsByRoomId(cls, roomId):
        #room = cls.objects.get(roomId=roomId)

    @staticmethod
    def getUserIdsByRoomId(roomId):
        room = Room.objects.get(roomId=roomId)
        profiles = room.roomProfiles.all()
        userIds = [str(profile.user.userid) for profile in profiles]
        return userIds

    @staticmethod
    def createRoom(currUser, currRoomName, currPassword):
        try :
            currRoom = Room.objects.create(
                roomName        = currRoomName,
                roomPassword    = hashPassword(currPassword),
            )
            currProfile = Profile.objects.filter(user=currUser, isAdmin=False).first()
            if not currProfile :
                currProfile = Profile.objects.create(
                    user        = currUser, 
                    isAdmin    = True,
                )
            currRoom.roomProfiles.add( currProfile )
            currRoom.save();

            return {
                'result': True,
                'redirect': f'/messenger/rooms/{currRoom.roomId}',
                'alert': f"New room '{currRoomName}' created with ID: '{currRoom.roomId}', Password: '{currPassword}'",
            }
        except Exception as err :
            print("Error captured --> ", err)
            return {
                'result': False,
                'redirect': f'/messenger/rooms/',
                'alert': f"Creating New room '{currRoomName}' failed!!! please Refresh the page and try again. if the problem continues feel free to contact customer support! '",
            }

    @staticmethod
    def joinRoom(currUser, currRoomId, currPassword):
        try :
            currRoom = Room.getById( getRoomId=currRoomId )
    
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
            
            currProfile = Profile.objects.filter(user=currUser, isAdmin=False).first()
            if not currProfile :
                currProfile = Profile.objects.create(
                    user        = currUser, 
                    isAdmin    = False,
                )
            currRoom.roomProfiles.add( currProfile )
            currRoom.save()

            return {
                'result': True,
                'redirect': f'/messenger/rooms/{currRoomId}',
                'alert': "Join successful!",
            }
        except Exception as err :
            print("Error captured --> ", err)
            return {
                'result': False,
                'redirect': f'/messenger/rooms/',
                'alert': f"Joining New room '{currRoomId}' failed!!! please Refresh the page and try again. if the problem continues feel free to contact customer support! '",
            }



###def getUserRoomsList(currUser) :
###    userRoomsList = []
###    try :
###        ### here everything will be Queryset< Object >
###        profiles = currUser.profile_set.all()
###        ###print(f"profiles: {profiles}")
###        profileRooms = [ pr.room_set.all() for pr in profiles ]
###        ###print(f"profileRooms: {profileRooms}")
###        userRoomsList = []
###        for room in profileRooms:
###            roomData = room.values()[0]
###            ###print(f"roomData: {roomData}")
###            custRoomData = {'roomId': roomData['roomId'], 'roomName':roomData.get('roomName'), 'updatedAt':roomData.get('updatedAt') }
###            userRoomsList.append(custRoomData)
###    except Exception as err:
###        print("captured error!!! @[Room.getUserRoomsList]")
###    return userRoomsList

#def getUserRoomCustomDetail(currRoomId) :
#    currRoom            = Room.getById( getRoomId=currRoomId )
#    customReturnValue   = { 'roomId': currRoom.roomId, 'roomName': currRoom.roomName, 'roomPassword': currRoom.roomPassword,'roomProfiles': currRoom.roomProfiles, 'createdAt': currRoom.createdAt, 'updatedAt': currRoom.updatedAt }
#    return customReturnValue


###async def createRoom(currUser, currRoomName, currPassword):
###    #print(f"------->> {currUser.username}")
###    #try :
###        print(f"------->> {currUser.username}")
###        currRoom = await Room.objects.create(
###            roomName        = currRoomName,
###            roomPassword    = hashPassword(currPassword),
###        )
###        print(f"------->> {currRoom}")
###        #currProfile = Profile.objects.get(user=currUser, isAdmin=False,)
###        #if not currProfile :
###        #    currProfile = Profile.objects.create(
###        #        user        = currUser, 
###        #        isAdmin    = False,
###        #    )
###        #currRoom.roomProfiles.add( currProfile )
###        currRoom.save();
###        return {
###            'result': True,
###            'redirect': f'/messenger/rooms/{currRoom.roomId}',
###            'alert': f"New room '{currRoomName}' created with ID: '{currRoom.roomId}', Password: '{currPassword}'",
###        }
###    #except Exception as err :
###    #    return {
###    #        'result': False,
###    #        'redirect': f'/messenger/rooms/',
###    #        'alert': f"Creating New room '{currRoomName}' failed!!! please Refresh the page and try again. if the problem continues feel free to contact customer support! '",
###    #    }