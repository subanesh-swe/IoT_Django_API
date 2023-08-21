from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from .models import UserAccount as User
from django.utils.translation import gettext_lazy as _


class loginForm(forms.Form):
    class Meta:
        model = User
        fields = ['username', 'password']
    
    #def clean_username(self):
    #    username = self.cleaned_data.get('username')
    #    if not username or username=='':
    #        raise forms.ValidationError("Username cannot be empty!!!")
    #    if User.objects.filter(username=username).exists():
    #        raise forms.ValidationError("Invalid Username!!!")
    #    return username
    
    #def clean_password(self):
    #    password = self.cleaned_data.get('password')
    #    if not password or password=='':
    #        raise forms.ValidationError("Username cannot be empty!!!")
    #    if User.objects.filter(password=password).exists():
    #        raise forms.ValidationError("Invalid Username!!!")
    #    return password

    
class signupForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email is already taken.")
        return email

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("This username is already taken.")
        return username

    def save(self, commit=True):
        user = super(signupForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        user.username = self.cleaned_data['username']
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user

