from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from assets.views import AssetViewSet
from dashboard.api import DashboardSummaryView
from findings.views import FindingViewSet
from knowledge_base.views import VulnerabilityRuleViewSet
from scan_profiles.views import ScanProfileViewSet
from scans.views import ScanExecutionViewSet

router = DefaultRouter()
router.register(r'assets', AssetViewSet)
router.register(r'scan-profiles', ScanProfileViewSet)
router.register(r'scans', ScanExecutionViewSet)
router.register(r'findings', FindingViewSet)
router.register(r'knowledge-rules', VulnerabilityRuleViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/dashboard/summary/', DashboardSummaryView.as_view(), name='dashboard-summary'),
    path('', include('dashboard.urls')),
]
