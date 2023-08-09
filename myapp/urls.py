from django.urls import path
from . import views

urlpatterns = [
    path('',views.login_view, name='Login'),
    #>>>CRUD on Users
    path('register/', views.register_user, name='register'),
    path('deleteUsers/<int:id>', views.remove_user,name="deleteUser"),
    path('listUsers/',views.list_users,name="users-list"),
    path('updateUsers/<int:id>',views.updateuser,name="update-users"),
    # >>>CRUD on API 
    path('ProtectedAPI/',views.listAPI, name='APIS'),
    path('deleteAPI/<int:id>', views.deleteApi,name="deleteApi"),
    path('createAPI/',views.createAPI,name="api-create"),
    path('updateAPI/<int:id>', views.updateApi,name="update-Api"),

    path('mapAPI/<int:id>',views.mapApi,name="map"),
    path('logout/',views.logout,name="logout_button")
]