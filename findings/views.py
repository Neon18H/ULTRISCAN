from rest_framework import viewsets
from accounts.permissions import IsAnalystOrAdmin
from .models import Finding
from .serializers import FindingSerializer


class FindingViewSet(viewsets.ModelViewSet):
    queryset = Finding.objects.select_related('scan_execution').all()
    serializer_class = FindingSerializer
    permission_classes = [IsAnalystOrAdmin]
