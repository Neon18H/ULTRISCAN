from django.urls import path

from scans.views import ScanCreateView, ScanDetailView, ScanListView

from .views import (
    AssetCreateView,
    AssetDetailView,
    AssetListView,
    AssetUpdateView,
    DashboardHomeView,
    FindingDetailView,
    ExecutiveSummaryPdfView,
    FindingListView,
    FindingsTechnicalPdfView,
    KnowledgeBaseListView,
    ScanProfileListView,
)

urlpatterns = [
    path('', DashboardHomeView.as_view(), name='dashboard-home'),
    path('assets/', AssetListView.as_view(), name='assets-list'),
    path('assets/new/', AssetCreateView.as_view(), name='assets-create'),
    path('assets/<int:pk>/', AssetDetailView.as_view(), name='assets-detail'),
    path('assets/<int:pk>/edit/', AssetUpdateView.as_view(), name='assets-edit'),
    path('scan-profiles/', ScanProfileListView.as_view(), name='scan-profiles-list'),
    path('scans/new/', ScanCreateView.as_view(), name='scans-create'),
    path('scans/create/', ScanCreateView.as_view(), name='scans-create-legacy'),
    path('scans/', ScanListView.as_view(), name='scans-list'),
    path('scans/<int:pk>/', ScanDetailView.as_view(), name='scans-detail'),
    path('findings/', FindingListView.as_view(), name='findings-list'),
    path('findings/export/technical-pdf/', FindingsTechnicalPdfView.as_view(), name='findings-export-technical-pdf'),
    path('reports/executive-summary.pdf', ExecutiveSummaryPdfView.as_view(), name='reports-executive-pdf'),
    path('findings/<int:pk>/', FindingDetailView.as_view(), name='findings-detail'),
    path('knowledge-base/', KnowledgeBaseListView.as_view(), name='knowledge-base-list'),
]
