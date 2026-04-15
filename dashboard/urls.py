from django.urls import path

from .views import AssetDetailView, AssetListView, DashboardHomeView, FindingDetailView, FindingListView, KnowledgeBaseListView, LaunchScanView, ScanDetailView, ScanListView, ScanProfileListView

urlpatterns = [
    path('', DashboardHomeView.as_view(), name='dashboard-home'),
    path('assets/', AssetListView.as_view(), name='assets-list'),
    path('assets/<int:pk>/', AssetDetailView.as_view(), name='assets-detail'),
    path('assets/<int:asset_id>/launch-scan/', LaunchScanView.as_view(), name='assets-launch-scan'),
    path('scan-profiles/', ScanProfileListView.as_view(), name='scan-profiles-list'),
    path('scans/', ScanListView.as_view(), name='scans-list'),
    path('scans/<int:pk>/', ScanDetailView.as_view(), name='scans-detail'),
    path('findings/', FindingListView.as_view(), name='findings-list'),
    path('findings/<int:pk>/', FindingDetailView.as_view(), name='findings-detail'),
    path('knowledge-base/', KnowledgeBaseListView.as_view(), name='knowledge-base-list'),
]
