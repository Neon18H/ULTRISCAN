from django.urls import path

from .views import (
    AccountLoginView,
    AccountLogoutView,
    OrganizationSettingsView,
    ProfileView,
    RegisterView,
    TeamManagementView,
)

urlpatterns = [
    path('login/', AccountLoginView.as_view(), name='login'),
    path('logout/', AccountLogoutView.as_view(), name='logout'),
    path('register/', RegisterView.as_view(), name='register'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('organization/settings/', OrganizationSettingsView.as_view(), name='organization-settings'),
    path('organization/team/', TeamManagementView.as_view(), name='team-management'),
]
