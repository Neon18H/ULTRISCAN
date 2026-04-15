from rest_framework import viewsets

from accounts.permissions import TenantAccessPermission
from core.tenant_api import TenantModelViewSetMixin

from .models import Finding
from .serializers import FindingSerializer


class FindingViewSet(TenantModelViewSetMixin, viewsets.ModelViewSet):
    queryset = Finding.objects.select_related('scan_execution').all()
    serializer_class = FindingSerializer
    permission_classes = [TenantAccessPermission]

    def perform_create(self, serializer):
        org = self.get_organization()
        scan_execution = serializer.validated_data.get('scan_execution')
        if scan_execution.organization_id != org.id:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied('Escaneo fuera de la organización activa.')
        serializer.save(organization=org)
