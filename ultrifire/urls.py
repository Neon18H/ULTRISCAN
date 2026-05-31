from django.urls import path

from .views import FirewallCommandView, PolicyActionView, PolicyListView, PolicyPreviewView

urlpatterns = [
    path('policies/', PolicyListView.as_view(), name='ultrifire-policies'),
    path('policies/<str:policy_id>/preview.json', PolicyPreviewView.as_view(), name='ultrifire-policy-preview'),
    path('policies/<str:policy_id>/<str:action>/', PolicyActionView.as_view(), name='ultrifire-policy-action'),
    path('commands/', FirewallCommandView.as_view(), name='ultrifire-command'),
]
