from rest_framework import viewsets

from accounts.permissions import TenantAccessPermission
from core.tenant_api import TenantModelViewSetMixin

from .models import ScanProfile
from .serializers import ScanProfileSerializer


class ScanProfileViewSet(TenantModelViewSetMixin, viewsets.ModelViewSet):
    queryset = ScanProfile.objects.all()
    serializer_class = ScanProfileSerializer
    permission_classes = [TenantAccessPermission]
