from django.db.models import Count
from django.views.generic import DetailView, ListView, TemplateView

from assets.models import Asset
from findings.models import Finding
from knowledge_base.models import VulnerabilityRule
from scans.models import ScanExecution


class DashboardHomeView(TemplateView):
    template_name = 'dashboard/home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assets_total'] = Asset.objects.count()
        context['recent_scans'] = ScanExecution.objects.order_by('-created_at')[:5]
        context['findings_by_severity'] = Finding.objects.values('severity').annotate(total=Count('id'))
        return context


class AssetListView(ListView):
    model = Asset
    template_name = 'dashboard/assets_list.html'


class AssetDetailView(DetailView):
    model = Asset
    template_name = 'dashboard/asset_detail.html'


class ScanListView(ListView):
    model = ScanExecution
    template_name = 'dashboard/scans_list.html'


class ScanDetailView(DetailView):
    model = ScanExecution
    template_name = 'dashboard/scan_detail.html'


class FindingListView(ListView):
    model = Finding
    template_name = 'dashboard/findings_list.html'


class FindingDetailView(DetailView):
    model = Finding
    template_name = 'dashboard/finding_detail.html'


class KnowledgeBaseListView(ListView):
    model = VulnerabilityRule
    template_name = 'dashboard/knowledge_base_list.html'
