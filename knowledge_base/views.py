from rest_framework import viewsets

from accounts.permissions import TenantAccessPermission

from .models import VulnerabilityRule
from .serializers import VulnerabilityRuleSerializer


class VulnerabilityRuleViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = VulnerabilityRule.objects.select_related('product').all()
    serializer_class = VulnerabilityRuleSerializer
    permission_classes = [TenantAccessPermission]
