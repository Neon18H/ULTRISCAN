from rest_framework import viewsets
from accounts.permissions import IsAnalystOrAdmin
from .models import Asset
from .serializers import AssetSerializer


class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer
    permission_classes = [IsAnalystOrAdmin]
