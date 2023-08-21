from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import UserAccount

#view additional info in custom place of page
fields = list(UserAdmin.fieldsets)

#fields[1] = ('Personal Info', {'fields': ('first_name', 'last_name', 'email')}) ##default
#fields[1] = ('Personal Info', {'fields': ('first_name', 'last_name', 'email', 'phone', 'nickname')}) ##edited

fields.insert(2, ('App data', {'fields': ('userid', 'userdata' )}))

UserAdmin.fieldsets = tuple(fields)

admin.site.register(UserAccount, UserAdmin) 


from django.contrib.sessions.models import Session
class SessionAdmin(admin.ModelAdmin):
    def _session_data(self, obj):
        return obj.get_decoded()
    list_display = ['session_key', '_session_data', 'expire_date']
admin.site.register(Session, SessionAdmin)

###another method for above 
###view additional info in custom place of page
###class CustomUserAdmin(UserAdmin):
###    fields_temp = list(UserAdmin.fieldsets)

###    #fields[1] = ('Personal Info', {'fields': ('first_name', 'last_name', 'email')}) ##default
###    #fields[1] = ('Personal Info', {'fields': ('first_name', 'last_name', 'email', 'phone', 'nickname')}) ##edited
###    print("-------------", fields_temp)
###    fields_temp.insert(2, ('App data', {'fields': ('userid', 'userdata' )}))
###    print("-------------", fields_temp)

###    UserAdmin.fieldsets = tuple(fields_temp)

###admin.site.register(UserAccount, CustomUserAdmin) 

#admin.site.register(UserAccounts, UserAdmin) #creates custom user

##view custom user, displays at end

#class CustomUserAdmin(UserAdmin):
#    fieldsets =(
#        *UserAdmin.fieldsets,
#        (
#            'Additional Info',
#            {
#                'fields':(
#                    'phone',
#                    'nickname'
#                )
#            }
            
#        )
#    )
#admin.site.register(UserAccounts, CustomUserAdmin) 
