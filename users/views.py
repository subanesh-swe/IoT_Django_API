from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from . import forms
from .models import UserAccount as User
#from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.core.exceptions import PermissionDenied
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer, LoginSerializer, SignupSerializer
from rest_framework.authentication import SessionAuthentication
from rest_framework import permissions, status

def responseMaker(success=False, report='', processData= {}, outputData={}, errorData= {}) -> dict:
    return {'success': success, 'report': report, 'response': {'processData': processData, 'outputData': outputData, 'errorData': errorData }}

class UserSessionAPIView(APIView):
    #@method_decorator(login_required)
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (SessionAuthentication,)
    def get(self, request):
        responseData = {}
        try :
            print(f"is auth: {request.user}")
            if not request.user.is_authenticated:
                raise PermissionDenied
            outputData = UserSerializer(request.user).data
            responseData = responseMaker(success=True, report="User Session Valid.", processData={}, outputData=outputData, errorData= {})
            
            #users = request.user
            #serializer = UserSerializer(users)
            #return Response(serializer.data)
        except PermissionDenied as errors:
            print(f"usersession => {str(errors)}")
            responseData = responseMaker(success=False, report="User Session Invalid.", processData={}, outputData={}, errorData={'error': str(errors)})
        except Exception as errors:
            responseData = responseMaker(success=False, report="Something went wrong.", processData={}, outputData={}, errorData={'error': str(errors)})
        print(f"user session res: {responseData}")  
        return JsonResponse(responseData, status=202)
    #def handle_no_permission(self):
    #    responseData = responseMaker(success=False, report="Something went wrong.", processData={}, outputData={}, errorData={})
    #    return Response(responseData)
    #def handle_no_permission(self):
    #    ret    urn permission_denied(self.request, message='You do not have permission to access this page.')

class UserAPIView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (SessionAuthentication,)
    def get(self, request):
        responseData = {}
        try :
            outputData = UserSerializer(request.data).data
            responseData = Response(responseMaker(success=True, report="User Fetch Success.", processData=request.data, outputData=outputData, errorData= {}), status=status.HTTP_202_ACCEPTED)
        except Exception as errors:
            responseData = Response(responseMaker(success=False, report="Something went wrong.", processData=request.data, outputData={}, errorData={'error': str(errors)}), status.HTTP_500_INTERNAL_SERVER_ERROR)
        return responseData

    def post(self, request):
        responseData = {}
        try :
            outputData = UserSerializer(request.data).data
            responseData = Response(responseMaker(success=True, report="User Fetch Success.", processData=request.data, outputData=outputData, errorData= {}), status=status.HTTP_202_ACCEPTED)
        except Exception as errors:
            responseData = Response(responseMaker(success=False, report="Something went wrong.", processData=request.data, outputData={}, errorData={'error': str(errors)}), status.HTTP_500_INTERNAL_SERVER_ERROR)
        return responseData

class LoginAPIView(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (SessionAuthentication,)
    #permission_classes = [permissions.IsAuthenticated]
    #authentication_classes = [SessionAuthentication]
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
        
    def post(self, request):
        responseData = {}
        try :
            serializer = LoginSerializer(data=request.data)
            ## if serializer.is_valid(raise_exception=True): ## this will send validation errors automatically
            if serializer.is_valid():
                user = serializer.validated_data['user']
                login(request, user)
                responseData = responseMaker(success=True, report="Login Successful.", processData=serializer.data, outputData=UserSerializer(user).data, errorData= {})
            else :
                responseData = responseMaker(success=False, report="Login Unsuccessful.", processData=serializer.data, outputData={}, errorData=serializer.errors)
        except Exception as errors:
            responseData = responseMaker(success=False, report="Something went wrong.", processData=request.data, outputData={}, errorData={'error': str(errors)})
        print(f"login api -> response: {responseData}")
        return Response(responseData)

class SignupAPIView(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (SessionAuthentication,)
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
        
    def post(self, request):
        responseData = {}
        try :
            serializer = SignupSerializer(data=request.data)
            ## if serializer.is_valid(raise_exception=True): ## this will send validation errors automatically
            if serializer.is_valid():
                #serializer.save()
                user = serializer.create(serializer.validated_data)
                responseData = responseMaker(success=True, report="Signup Successful.", processData=serializer.data, outputData=UserSerializer(user).data, errorData= {})
            else :
                responseData = responseMaker(success=False, report="Signup Unsuccessful.", processData=serializer.data, outputData={}, errorData=serializer.errors)
        except Exception as errors:
            responseData = responseMaker(success=False, report="Something went wrong.", processData=request.data, outputData={}, errorData={'error': str(errors)})
        return Response(responseData)


class LogoutAPIView(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        logout(request)
        return Response(responseMaker(success=True, report="Logout Successful.", processData=request.data, outputData={}, errorData= {}),status=status.HTTP_200_OK)

def userLogout(request):
    logout(request)
    return redirect('home')

def userLogin(request):
    if request.method == 'POST':
        form = forms.loginForm(request.POST)
        if form.is_valid():
            username = request.POST.get('username')
            password = request.POST.get('password')
            print("username", username,"password", password)
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return JsonResponse({'result': True, 'redirect': '/messenger', 'alert': 'Login successful'})
            else:
                return JsonResponse({'result': False, 'redirect': '/users/login', 'alert': 'Invalid username or password'})
        else:
            errors = {}
            for field, error_list in form.errors.items():
                errors[field] = error_list[0]
            return JsonResponse({'result': False, 'redirect': '/users/login', 'alert': errors})
    else:
        form = forms.loginForm( request.POST)
    return render(request, 'users/login.html', {'form': form})

# method 1 (more optimized) :

def userSignup(request):
    if request.method == 'POST':
        #print("request.body:",request.body)
        #print("request.POST:",request.POST)
        form = forms.signupForm( request.POST )
        if form.is_valid():
            form.save()
            #print("form",form)
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(request, username=username, password=password)
            login(request, user)
            return JsonResponse({'result':True, 'redirect': '/users/login', 'alert': "Account created successfully"})
            #messages.success(request, f'Account created for {username}!')
            #return redirect('/messenger')
        else:
            #print("form.errors:",form.errors)
            #return JsonResponse({'result':False, 'alert': form.errors})
            errors = {}
            for field, error_list in form.errors.items():
                errors[field] = error_list[0]
            print("form.errors:",form.errors)
            return JsonResponse({'result':False, 'redirect': '/users/signup', 'alert': errors})
    else:
        form = forms.signupForm(request.POST)
    return render(request, 'users/signup.html', {'form': form})


# headers shouls be changed

#function formSubmitHandler(event, formId) {
#    event.preventDefault();
#    const formData = new FormData(document.getElementById(formId));
#    //console.log(JSON.stringify(Object.fromEntries(formData.entries())));
#    const data = Object.fromEntries(formData.entries());
#    console.log("posting data = " + JSON.stringify(data));
#    //fetch('/messenger/rooms', {
#    fetch(window.location.pathname, {
#        method: 'POST',
#        headers: {
#            'Content-Type': 'application/json',
#            'X-CSRFToken': csrfToken,
#        },
#        body: JSON.stringify(data)
#    })
#        .then(response => response.json())
#        .then(data => {
#            console.log("response data = " + JSON.stringify(data));
#            if (data.result === true) {
#                //alert(`Result : true -> ${JSON.stringify(data)}`);
#                window.location.href = data.redirect;
#            } else {
#                alert(data.alert);
#            }
#        })
#        .catch(error => {
#            alert("Something went wrong, Try again after sometime!!!");
#            console.error(error);
#        });
#}


##method 2 (own auth) (form handler is same as method 1):

#from django.shortcuts import render, redirect
#from django.contrib import messages
#from django.contrib.auth import authenticate, login
#from django.http import JsonResponse
#from django.contrib.auth.models import User
#import json

#def signup(request):
#    if request.method == 'POST':
#        received_json_data = json.loads(request.body)
#        username = received_json_data.get('username')
#        email = received_json_data.get('email')
#        password1 = received_json_data.get('password1')
#        password2 = received_json_data.get('password2')

#        returnData = {'result': True, 'redirect': '/messenger', 'alert': 'User created successfully!!!'}

#        if password1 != password2:
#            returnData.update({'result': False, 'redirect': '/users/signup', 'alert': 'Passwords do not match!!!'})

#        if User.objects.filter(username=username).exists():
#            returnData.update({'result': False, 'redirect': '/users/signup', 'alert': 'Username already taken!!!'})

#        if User.objects.filter(email=email).exists():
#            returnData.update({'result': False, 'redirect': '/users/signup', 'alert': 'Email already taken!!!'})
            
#        if returnData['result'] :
#            user = User.objects.create_user(username=username, email=email, password=password1)
#            user.save()
#            user = authenticate(request, username=username, password=password1)
#            login(request, user)

#        return JsonResponse(returnData)

#    else:
#        return render(request, 'users/signup.html')

## method 3 (default method) :

#def signup(request):
#    if request.method == 'POST':
#        print("request.POST:",request.POST)
#        form = forms.signupForm(request.POST)
#        if form.is_valid():
#            form.save()
#            #print("form",form)
#            #user = authenticate(request, username=username, password=password)
#            #login(request, user)
#            username = form.cleaned_data.get('username')
#            return JsonResponse({'result':True, 'alert': "Account created successfully"})
#            #messages.success(request, f'Account created for {username}!')
#            #return redirect('/messenger')
#        else:
#            print("form.errors:",form.errors)
#            #return JsonResponse({'result':False, 'alert': form.errors})
#            errors = {}
#            for field, error_list in form.errors.items():
#                errors[field] = error_list[0]
#            return JsonResponse({'result':False, 'alert': errors})
#    else:
#        form = forms.signupForm(request.POST)
#    return render(request, 'users/signup.html', {'form': form})


#function formSubmitHandler(event, formId) {
#    event.preventDefault();
#    const formData = new FormData(document.getElementById(formId));
#    console.log("posting data = " + JSON.stringify(formData));
#    fetch(window.location.pathname, {
#        method: 'POST',
#        headers: {
#            'Content-Type': 'application/x-www-form-urlencoded',
#            'X-CSRFToken': csrfToken,
#        },
#        body: new URLSearchParams(formData).toString()
#    })
#        .then(response => response.json())
#        .then(data => {
#            console.log("response data = " + JSON.stringify(data));
#            if (data.result === true) {
#                //alert(`Result : true -> ${JSON.stringify(data)}`);
#                window.location.href = data.redirect;
#            } else {
#                alert(data.alert);
#            }
#        })
#        .catch(error => {
#            alert("Something went wrong, Try again after sometime!!!");
#            console.error(error);
#        });
#}