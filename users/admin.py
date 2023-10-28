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



# from django.contrib import admin
from django.contrib.admin.models import LogEntry, DELETION
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.urls import reverse

@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    date_hierarchy = 'action_time'
    readonly_fields = ('action_time',)
    list_filter = ['user', 'content_type']
    search_fields = ['object_repr', 'change_message']
    list_display = ['__str__', 'content_type', 'action_time', 'user', 'object_link']

    # keep only view permission
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def object_link(self, obj):
        if obj.action_flag == DELETION:
            link = obj.object_repr
        else:
            ct = obj.content_type
            try:
                link = mark_safe('<a href="%s">%s</a>' % (
                                 reverse('admin:%s_%s_change' % (ct.app_label, ct.model),
                                         args=[obj.object_id]),
                                 escape(obj.object_repr),
                ))
            except NoReverseMatch:
                link = obj.object_repr
        return link
    object_link.admin_order_field = 'object_repr'
    object_link.short_description = 'object'

    def queryset(self, request):
        return super(LogEntryAdmin, self).queryset(request) \
            .prefetch_related('content_type')