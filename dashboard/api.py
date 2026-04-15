from django.db.models import Count
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from assets.models import Asset
from findings.models import Finding
from scans.models import ScanExecution, ServiceFinding


class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            'total_assets': Asset.objects.count(),
            'recent_scans': list(ScanExecution.objects.order_by('-created_at').values('id', 'status', 'created_at')[:5]),
            'findings_by_severity': list(Finding.objects.values('severity').annotate(total=Count('id'))),
            'top_vulnerable_products': list(ServiceFinding.objects.exclude(product='').values('product').annotate(total=Count('id')).order_by('-total')[:5]),
            'top_ports': list(ServiceFinding.objects.values('port').annotate(total=Count('id')).order_by('-total')[:5]),
            'latest_findings': list(Finding.objects.order_by('-created_at').values('id', 'title', 'severity', 'status')[:10]),
        })
