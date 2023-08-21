from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
import uuid
import random


class UserAccount(AbstractUser) :
    #phone_number = models.IntegerField(null=True, blank=True)
    userid = models.UUIDField(default='', primary_key=True)
    userdata = models.JSONField(null=True, blank=True, default=dict)

    def __init__(self, *args, **kwargs):
        #print("init user -------------")
        super(UserAccount, self).__init__(*args, **kwargs)
        if not self.userid:
            self.userid = self.getUniqueId()
            #print("init user ------------- UUid generated ->", self.userid)
        #if UserAccount.getById(self.userid):
        #    self.userid = self.getUniqueId()

    ###""" get uniqueId """###
    @staticmethod
    def getUniqueId():
        while True:
            #print("creating userId")
            #letters = str(uuid.uuid4().hex) + str(uuid.uuid4().hex)
            #uniqueId = ''.join(random.choice(letters) for _ in range(16))
            uniqueId = uuid.uuid4()
            if not UserAccount.getById(uniqueId):
                return uniqueId

    @staticmethod
    def getById(getUserId):
        currUser = None
        try:
            currUser = UserAccount.objects.get(pk=getUserId)
        except Exception as err:
            #print(f"Error captured @[User.getById] {err}")
            currUser = None
        return currUser
    
    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['email'], name='unique_email'),
            models.UniqueConstraint(fields=['username'], name='unique_username')
        ]

    def clean(self):
        super().clean()
        if UserAccount.objects.filter(email=self.email).exclude(pk=self.pk).exists():
            raise ValidationError({'email': 'Email already exists'})
        if UserAccount.objects.filter(username=self.username).exclude(pk=self.pk).exists():
            raise ValidationError({'username': 'Username already exists'})

#from django.contrib.auth.base_user import BaseUserManager
#from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin

#class UserAccountManager(BaseUserManager):
#    def create_user(self, username, email, password=None):
#        if not username:
#            raise ValueError('An username is required.')
#        if not email:
#            raise ValueError('An email is required.')
#        if not password:
#            raise ValueError('A password is required.')
#        email = self.normalize_email(email)
#        user = self.create_user(username=username, email=email, password=password)
#        user.save()
#        return user
    
#    def create_superuser(self, username, email, password=None):
#        if not username:
#            raise ValueError('An username is required.')
#        if not email:
#            raise ValueError('An email is required.')
#        if not password:
#            raise ValueError('A password is required.')
#        user = self.create_user(username=username, email=email, password=password)
#        user.is_superuser = True
#        user.save()
#        return user

#    def create_superuser(self, username, email, password=None):
#        user = self.create_user(username=username, email=email, password=password)
#        user.is_superuser = True
#        user.save()
#        return user

#    def get_by_natural_key(self, username):
#        return self.get(username=username)

#    def get_by_email(self, email):
#        return self.get(email=email)

#    def get_by_username(self, username):
#        return self.get(username=username)

#    def get_by_id(self, id):
#        return self.get(id=id)

#    def get_by_pk(self, pk):
#        return self.get(pk=pk)

#    #def get_queryset(self):
#    #    return super().get_queryset().filter(is_deleted=False)


#class UserAccount(AbstractBaseUser, PermissionsMixin):
#    userid = models.UUIDField(default= '', primary_key=True)
#    email = models.EmailField(max_length=255, unique=True)
#    username = models.CharField(max_length=255, unique=True)
#    userdata = models.JSONField(null=True, blank=True, default=dict)
#    USERNAME_FIELD = 'username'
#    REQUIRED_FIELDS = ['email']
#    objects = UserAccountManager()

#    def __str__(self):
#        return self.username

#    def __init__(self, *args, **kwargs):
#        #print("init user -------------")
#        super(UserAccount, self).__init__(*args, **kwargs)
#        if not self.userid:
#            self.userid = self.getUniqueId()
#            #print("init user ------------- UUid generated ->", self.userId)

#    ###""" get uniqueId """###
#    @staticmethod
#    def getUniqueId():
#        while True:
#            #print("creating userId")
#            letters = str(uuid.uuid4().hex) + str(uuid.uuid4().hex)
#            uniqueId = ''.join(random.choice(letters) for _ in range(16))
#            if not UserAccount.getById(uniqueId):
#                return uniqueId

#    @staticmethod
#    def getById(getUserId):
#        currUser = None
#        try:
#            currUser = UserAccount.objects.get(pk=getUserId)
#        except Exception as err:
#            print(f"Error captured @[User.getById] {err}")
#            currUser = None
#        return currUser
    
    


#import uuid
#from django.contrib.auth.models import AbstractUser
#from django.db import models
#import jsonfield

#class CustomUserModel(AbstractUser):
#    UserId = models.UUIDField(default=uuid.uuid4, editable=False)
    #userdata = models.JSONField(null=True, blank=True, default={})
