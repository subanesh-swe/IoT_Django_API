from typing import Required
from django.contrib.auth import authenticate, login
from django.contrib.auth.password_validation import validate_password
from .models import UserAccount as User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = authenticate(request=self.context.get('request'), username=username, password=password)

            if not user:
                raise serializers.ValidationError({'validationError': 'Invalid username or password.'}, code='authorization')

            data['user'] = user

        else:
            raise serializers.ValidationError({'validationError': 'Must include "username" and "password".'}, code='authorization')
        print(f"s data:{data}")
        return data
    
class SignupSerializer(serializers.ModelSerializer):
    email       = serializers.EmailField(required=True)
    username    = serializers.CharField(required=True)
    password1   = serializers.CharField(required=True)
    password2   = serializers.CharField(required=True)
    #password1   = serializers.CharField(write_only=True, required=True)
    #password2   = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        #fields = '__all__'
        fields = ('email', 'username', 'password1', 'password2')

    def validate(self, data):
        email       = data.get('email')
        username    = data.get('username')
        password1   = data.get('password1')
        password2   = data.get('password2')
        if password1 != password2:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        try:
            validate_password(password1, self.instance)
        #except ValidationError as errors:
        except Exception as errors:
            raise serializers.ValidationError({"password": errors.messages})

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "Email already exists."})

        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError({"username": "Username already exists."})

        return data

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
            username=validated_data['username'],
            #password=validated_data['password1'] # this will not hash password
        )
        user.set_password(validated_data['password1'])
        user.save()
        return user


#class SignupSerializer(serializers.ModelSerializer):
#    email       = serializers.EmailField(required=True)
#    username    = serializers.CharField(required=True)
#    password1   = serializers.CharField(required=True)
#    password2   = serializers.CharField(required=True)

#    def validate_email(self, value):
#        if User.objects.filter(email=value).exists():
#            raise serializers.ValidationError({'validationError': "This email is already taken."})
#        return value

#    def validate_username(self, value):
#        if User.objects.filter(username=value).exists():
#            raise serializers.ValidationError({'validationError': "This username is already taken."})
#        return value

#    def create(self, validated_data):
#        user = User.objects.create_user(
#            username=validated_data['username'],
#            email=validated_data['email'],
#            password=validated_data['password1']
#        )
#        return user