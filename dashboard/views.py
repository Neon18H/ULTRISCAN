from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import OperationalError, ProgrammingError
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views import View
from django.views.generic import DetailView, ListView, TemplateView

from accounts.tenancy import TenantQuerysetMixin, get_active_organization
from assets.models import Asset
from findings.models import Finding
from knowledge_base.models import VulnerabilityRule
from scans.models import ScanExecution, ServiceFinding
from scans.tasks import run_scan_pipeline_task
from scan_profiles.models import ScanProfile

from .forms import LaunchScanForm


def safe_query(default, query_fn):
    try:
        return query_fn()
    except (ProgrammingError, OperationalError):
        return default


class DashboardHomeView(LoginRequiredMixin, TemplateView):
    template_name = 'dashboard/home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        org = get_active_organization(self.request.user)
        if not org:
            context.update({'assets_total': 0, 'recent_scans': [], 'findings_by_severity': [], 'open_vs_remediated': [], 'top_services': [], 'top_products': [], 'recent_activity': []})
            return context

        context['assets_total'] = safe_query(0, lambda: Asset.objects.filter(organization=org).count())
        context['recent_scans'] = safe_query([], lambda: list(ScanExecution.objects.filter(organization=org).order_by('-created_at')[:5]))
        context['findings_by_severity'] = safe_query([], lambda: list(Finding.objects.filter(organization=org).values('severity').annotate(total=Count('id'))))
        context['open_vs_remediated'] = safe_query([], lambda: list(Finding.objects.filter(organization=org).values('status').annotate(total=Count('id')).filter(status__in=['open', 'remediated'])))
        context['top_services'] = safe_query([], lambda: list(ServiceFinding.objects.filter(organization=org).exclude(service='').values('service').annotate(total=Count('id')).order_by('-total')[:5]))
        context['top_products'] = safe_query([], lambda: list(ServiceFinding.objects.filter(organization=org).exclude(product='').values('product').annotate(total=Count('id')).order_by('-total')[:5]))
        context['recent_activity'] = safe_query([], lambda: list(Finding.objects.filter(organization=org).order_by('-created_at')[:8]))
        return context


class AssetListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = Asset
    template_name = 'dashboard/assets_list.html'


class AssetDetailView(LoginRequiredMixin, TenantQuerysetMixin, DetailView):
    model = Asset
    template_name = 'dashboard/asset_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['launch_scan_form'] = LaunchScanForm(organization=self.get_organization())
        context['asset_scans'] = self.object.scan_executions.select_related('profile').order_by('-created_at')[:10]
        return context


class LaunchScanView(LoginRequiredMixin, View):
    def post(self, request, asset_id):
        org = get_active_organization(request.user)
        asset = get_object_or_404(Asset, id=asset_id, organization=org)
        form = LaunchScanForm(request.POST, organization=org)
        if not form.is_valid():
            messages.error(request, 'Perfil de escaneo inválido para tu organización.')
            return redirect(reverse('assets-detail', kwargs={'pk': asset.id}))

        profile = form.cleaned_data['profile']
        scan = ScanExecution.objects.create(
            organization=org,
            asset=asset,
            profile=profile,
            launched_by=request.user,
            status=ScanExecution.Status.PENDING,
        )
        run_scan_pipeline_task.delay(scan.id)
        messages.success(request, f'Escaneo #{scan.id} encolado correctamente.')
        return redirect(reverse('scans-detail', kwargs={'pk': scan.id}))


class ScanListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = ScanExecution
    template_name = 'dashboard/scans_list.html'


class ScanDetailView(LoginRequiredMixin, TenantQuerysetMixin, DetailView):
    model = ScanExecution
    template_name = 'dashboard/scan_detail.html'


class FindingListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = Finding
    template_name = 'dashboard/findings_list.html'


class FindingDetailView(LoginRequiredMixin, TenantQuerysetMixin, DetailView):
    model = Finding
    template_name = 'dashboard/finding_detail.html'


class KnowledgeBaseListView(LoginRequiredMixin, ListView):
    model = VulnerabilityRule
    template_name = 'dashboard/knowledge_base_list.html'


class ScanProfileListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = ScanProfile
    template_name = 'dashboard/scan_profiles_list.html'
