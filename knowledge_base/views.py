from rest_framework import viewsets
from accounts.permissions import IsAnalystOrAdmin
from .models import VulnerabilityRule
from .serializers import VulnerabilityRuleSerializer


class VulnerabilityRuleViewSet(viewsets.ModelViewSet):
    queryset = VulnerabilityRule.objects.select_related('product').all()
    serializer_class = VulnerabilityRuleSerializer
    permission_classes = [IsAnalystOrAdmin]
