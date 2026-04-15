from django.db.models import Count
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.tenancy import get_active_organization
from assets.models import Asset
from findings.models import Finding
from scans.models import ScanExecution, ServiceFinding


class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        org = get_active_organization(request.user)
        if not org:
            return Response({'detail': 'No organization membership'})
        return Response({
            'total_assets': Asset.objects.filter(organization=org).count(),
            'recent_scans': list(ScanExecution.objects.filter(organization=org).order_by('-created_at').values('id', 'status', 'created_at')[:5]),
            'findings_by_severity': list(Finding.objects.filter(organization=org).values('severity').annotate(total=Count('id'))),
            'top_vulnerable_products': list(ServiceFinding.objects.filter(organization=org).exclude(product='').values('product').annotate(total=Count('id')).order_by('-total')[:5]),
            'top_ports': list(ServiceFinding.objects.filter(organization=org).values('port').annotate(total=Count('id')).order_by('-total')[:5]),
            'latest_findings': list(Finding.objects.filter(organization=org).order_by('-created_at').values('id', 'title', 'severity', 'status')[:10]),
        })
