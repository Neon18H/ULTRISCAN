from rest_framework import viewsets

from accounts.permissions import TenantAccessPermission
from core.tenant_api import TenantModelViewSetMixin

from .models import Asset
from .serializers import AssetSerializer


class AssetViewSet(TenantModelViewSetMixin, viewsets.ModelViewSet):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer
    permission_classes = [TenantAccessPermission]
