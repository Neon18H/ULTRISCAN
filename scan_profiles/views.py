from rest_framework import viewsets
from accounts.permissions import IsAnalystOrAdmin
from .models import ScanProfile
from .serializers import ScanProfileSerializer


class ScanProfileViewSet(viewsets.ModelViewSet):
    queryset = ScanProfile.objects.all()
    serializer_class = ScanProfileSerializer
    permission_classes = [IsAnalystOrAdmin]
