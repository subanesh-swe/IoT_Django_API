from datetime import datetime
from django.urls import path
from django.contrib.auth.views import LoginView, LogoutView

from . import forms, views


urlpatterns = [
    #path('api/user/', views.UserAPIView.as_view(), name='apiuser' ),
    path('api/user/', views.UserSessionAPIView.as_view(), name='apiuser' ),
    path('api/login/', views.LoginAPIView.as_view(), name='apilogin' ),
    path('api/logout/', views.LogoutAPIView.as_view(), name='apilogout' ),
    path('api/signup/', views.SignupAPIView.as_view(), name='apisignup' ),
    path('signup/', views.userSignup, name='signup'),
    path('login/', views.userLogin, name='login' ),
    path('logout/', views.userLogout, name='logout'),
    #path('login/',
    #     LoginView.as_view
    #     (
    #         template_name='users/login.html',
    #         authentication_form=forms.loginForm,
    #         extra_context=
    #         {
    #             'title': 'Log in',
    #             'year' : datetime.now().year,
    #         }
    #     ),
    #     name='login'),
    #path('logout/', LogoutView.as_view(next_page='/'), name='logout'),

]
