from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.mixins import UserPassesTestMixin
from django.db import OperationalError, ProgrammingError
from django.db.models import Count
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import CreateView, DetailView, ListView, TemplateView, UpdateView

from accounts.tenancy import TenantQuerysetMixin, get_active_organization
from assets.models import Asset
from findings.models import Finding
from knowledge_base.models import VulnerabilityRule
from scan_profiles.models import ScanProfile
from scans.models import ScanExecution, ServiceFinding

from .forms import AssetForm


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
            context.update(
                {
                    'assets_total': 0,
                    'recent_scans': [],
                    'findings_by_severity': [],
                    'findings_total': 0,
                    'open_vs_remediated': [],
                    'top_services': [],
                    'top_products': [],
                    'recent_activity': [],
                    'latest_findings': [],
                    'kb_rules_total': 0,
                }
            )
            return context

        context['assets_total'] = safe_query(0, lambda: Asset.objects.filter(organization=org).count())
        context['recent_scans'] = safe_query([], lambda: list(ScanExecution.objects.filter(organization=org).order_by('-created_at')[:6]))

        severity_counts = safe_query(
            [], lambda: list(Finding.objects.filter(organization=org).values('severity').annotate(total=Count('id')))
        )
        severity_lookup = {item['severity']: item['total'] for item in severity_counts}
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        findings_total = sum(item['total'] for item in severity_counts)

        context['findings_by_severity'] = [
            {
                'severity': severity,
                'total': severity_lookup.get(severity, 0),
                'percentage': round((severity_lookup.get(severity, 0) / findings_total) * 100, 1) if findings_total else 0,
            }
            for severity in severity_order
        ]
        context['findings_total'] = findings_total
        context['open_vs_remediated'] = safe_query(
            [],
            lambda: list(
                Finding.objects.filter(organization=org)
                .values('status')
                .annotate(total=Count('id'))
                .filter(status__in=['open', 'remediated'])
            ),
        )
        context['top_services'] = safe_query(
            [],
            lambda: list(
                ServiceFinding.objects.filter(organization=org)
                .exclude(service='')
                .values('service')
                .annotate(total=Count('id'))
                .order_by('-total')[:6]
            ),
        )
        context['top_products'] = safe_query(
            [],
            lambda: list(
                ServiceFinding.objects.filter(organization=org)
                .exclude(product='')
                .values('product')
                .annotate(total=Count('id'))
                .order_by('-total')[:5]
            ),
        )

        latest_findings = safe_query(
            [],
            lambda: list(
                Finding.objects.filter(organization=org)
                .select_related('asset', 'service_finding')
                .order_by('-created_at')[:6]
            ),
        )
        context['latest_findings'] = latest_findings
        context['kb_rules_total'] = safe_query(0, lambda: VulnerabilityRule.objects.count())

        recent_scans = context['recent_scans']
        scan_activity = [
            {
                'kind': f'scan_{scan.status}',
                'title': f'Scan #{scan.id} · {scan.asset.name if scan.asset else "Sin activo"}',
                'description': f'Perfil: {scan.profile.name if scan.profile else "N/A"} · Estado {scan.get_status_display()}',
                'timestamp': scan.created_at,
            }
            for scan in recent_scans[:4]
        ]
        finding_activity = [
            {
                'kind': 'finding_created',
                'title': finding.title,
                'description': f'Nuevo finding {finding.get_severity_display()} en {finding.asset.name if finding.asset else "activo no asociado"}',
                'timestamp': finding.created_at,
            }
            for finding in latest_findings[:6]
        ]
        context['recent_activity'] = sorted(scan_activity + finding_activity, key=lambda item: item['timestamp'], reverse=True)[:8]
        return context


class AssetListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = Asset
    template_name = 'dashboard/assets_list.html'


class AssetCreateView(LoginRequiredMixin, CreateView):
    model = Asset
    form_class = AssetForm
    template_name = 'dashboard/asset_form.html'

    def dispatch(self, request, *args, **kwargs):
        self.organization = get_active_organization(request.user)
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        if not self.organization:
            messages.error(self.request, 'No tienes una organización activa.')
            return redirect('assets-list')
        form.instance.organization = self.organization
        messages.success(self.request, 'Activo creado correctamente.')
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('assets-detail', kwargs={'pk': self.object.pk})


class AssetUpdateView(LoginRequiredMixin, TenantQuerysetMixin, UpdateView):
    model = Asset
    form_class = AssetForm
    template_name = 'dashboard/asset_form.html'

    def form_valid(self, form):
        messages.success(self.request, 'Activo actualizado correctamente.')
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('assets-detail', kwargs={'pk': self.object.pk})


class AssetDetailView(LoginRequiredMixin, TenantQuerysetMixin, DetailView):
    model = Asset
    template_name = 'dashboard/asset_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['asset_scans'] = self.object.scan_executions.select_related('profile').order_by('-created_at')[:10]
        return context


class FindingListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = Finding
    template_name = 'dashboard/findings_list.html'

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .select_related('asset', 'service_finding', 'scan_execution')
            .order_by('-created_at')
        )


class FindingDetailView(LoginRequiredMixin, TenantQuerysetMixin, DetailView):
    model = Finding
    template_name = 'dashboard/finding_detail.html'


class KnowledgeBaseListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    model = VulnerabilityRule
    template_name = 'dashboard/knowledge_base_list.html'

    def test_func(self):
        return self.request.user.is_staff


class ScanProfileListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = ScanProfile
    template_name = 'dashboard/scan_profiles_list.html'
