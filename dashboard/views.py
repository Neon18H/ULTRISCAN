from django.contrib import messages
from datetime import timedelta
from django.core.exceptions import PermissionDenied
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.mixins import UserPassesTestMixin
from django.db import OperationalError, ProgrammingError
from django.db.models import Count, Max, Q
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.views.generic import CreateView, DetailView, ListView, TemplateView, UpdateView, View

from accounts.tenancy import TenantQuerysetMixin, get_active_organization
from assets.models import Asset
from findings.models import Finding
from knowledge_base.models import AdvisorySyncJob, ExternalAdvisory, VulnerabilityRule
from scan_profiles.models import ScanProfile
from scans.models import ScanExecution, ServiceFinding

from .forms import AssetForm
from .reports import build_executive_summary_pdf, build_technical_findings_pdf


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
                    'nvd_advisories_total': 0,
                    'nvd_recent_imported': 0,
                    'nvd_critical_high_total': 0,
                    'nvd_last_sync_at': None,
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
        context['nvd_advisories_total'] = safe_query(0, lambda: ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD).count())
        context['nvd_recent_imported'] = safe_query(
            0,
            lambda: ExternalAdvisory.objects.filter(
                source=ExternalAdvisory.Source.NVD,
                created_at__gte=timezone.now() - timedelta(days=7),
            ).count(),
        )
        context['nvd_critical_high_total'] = safe_query(
            0,
            lambda: ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD, severity__in=['critical', 'high']).count(),
        )
        context['nvd_last_sync_at'] = safe_query(
            None,
            lambda: AdvisorySyncJob.objects.filter(source=ExternalAdvisory.Source.NVD, finished_at__isnull=False)
            .order_by('-finished_at')
            .values_list('finished_at', flat=True)
            .first(),
        )

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


class FindingFilterMixin:
    severity_values = [choice[0] for choice in Finding.Severity.choices]
    status_values = [choice[0] for choice in Finding.Status.choices]
    confidence_values = [choice[0] for choice in Finding.Confidence.choices]

    def get_base_queryset(self):
        organization = get_active_organization(self.request.user)
        if not organization:
            raise PermissionDenied('No existe una organización activa para este usuario.')
        return (
            Finding.objects.filter(organization=organization)
            .select_related('asset', 'service_finding', 'scan_execution', 'raw_evidence')
            .order_by('-created_at')
        )

    def apply_filters(self, queryset):
        params = self.request.GET

        severity = params.get('severity')
        if severity in self.severity_values:
            queryset = queryset.filter(severity=severity)

        status = params.get('status')
        if status in self.status_values:
            queryset = queryset.filter(status=status)

        confidence = params.get('confidence')
        if confidence in self.confidence_values:
            queryset = queryset.filter(confidence=confidence)

        asset = params.get('asset', '').strip()
        if asset:
            queryset = queryset.filter(
                Q(asset__name__icontains=asset) |
                Q(asset__value__icontains=asset)
            )

        service = params.get('service', '').strip()
        if service:
            queryset = queryset.filter(service_finding__service__icontains=service)

        port = params.get('port', '').strip()
        if port.isdigit():
            queryset = queryset.filter(service_finding__port=int(port))

        date_from = params.get('date_from')
        if date_from:
            queryset = queryset.filter(created_at__date__gte=date_from)

        date_to = params.get('date_to')
        if date_to:
            queryset = queryset.filter(created_at__date__lte=date_to)

        query = params.get('query', '').strip()
        if query:
            queryset = queryset.filter(Q(title__icontains=query) | Q(description__icontains=query))

        return queryset

    def get_active_filter_chips(self):
        labels = {
            'severity': 'Severidad',
            'status': 'Estado',
            'confidence': 'Confidence',
            'asset': 'Activo',
            'service': 'Servicio',
            'port': 'Puerto',
            'date_from': 'Desde',
            'date_to': 'Hasta',
            'query': 'Búsqueda',
        }
        chips = []
        for key, label in labels.items():
            value = self.request.GET.get(key, '').strip()
            if value:
                chips.append({'label': label, 'value': value})
        return chips

    def get_querystring_without_page(self):
        params = self.request.GET.copy()
        params.pop('page', None)
        return params.urlencode()


class FindingListView(LoginRequiredMixin, TenantQuerysetMixin, FindingFilterMixin, ListView):
    model = Finding
    template_name = 'dashboard/findings_list.html'
    paginate_by = 20

    def get_queryset(self):
        queryset = self.apply_filters(self.get_base_queryset())
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        org = get_active_organization(self.request.user)
        context['organization'] = org
        context['severity_choices'] = Finding.Severity.choices
        context['status_choices'] = Finding.Status.choices
        context['confidence_choices'] = Finding.Confidence.choices
        context['active_filter_chips'] = self.get_active_filter_chips()
        context['result_count'] = self.object_list.count()
        context['current_querystring'] = self.get_querystring_without_page()
        return context


class FindingDetailView(LoginRequiredMixin, TenantQuerysetMixin, DetailView):
    model = Finding
    template_name = 'dashboard/finding_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        cve_id = ''
        if self.object.vulnerability_rule and self.object.vulnerability_rule.cve:
            cve_id = self.object.vulnerability_rule.cve.strip().upper()

        context['nvd_advisory'] = None
        context['nvd_references'] = []
        if cve_id:
            advisory = safe_query(
                None,
                lambda: ExternalAdvisory.objects.filter(cve_id=cve_id)
                .prefetch_related('references')
                .first(),
            )
            context['nvd_advisory'] = advisory
            if advisory:
                context['nvd_references'] = list(advisory.references.all()[:5])
        return context


class FindingsTechnicalPdfView(LoginRequiredMixin, FindingFilterMixin, View):
    def get(self, request, *args, **kwargs):
        queryset = self.apply_filters(self.get_base_queryset())
        org = get_active_organization(request.user)
        response = build_technical_findings_pdf(
            organization=org,
            findings=queryset,
            generated_by=request.user,
            applied_filters=self.get_active_filter_chips(),
        )
        return response


class ExecutiveSummaryPdfView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        org = get_active_organization(request.user)
        if not org:
            raise PermissionDenied('No existe una organización activa para este usuario.')
        findings = Finding.objects.filter(organization=org).select_related('asset')
        assets = Asset.objects.filter(organization=org)
        scans = ScanExecution.objects.filter(organization=org).select_related('asset', 'profile').order_by('-created_at')

        response = build_executive_summary_pdf(
            organization=org,
            findings=findings,
            assets=assets,
            scans=scans,
            generated_by=request.user,
        )
        return response


class KnowledgeBaseListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    model = ExternalAdvisory
    template_name = 'dashboard/knowledge_base_list.html'
    paginate_by = 25

    def get_queryset(self):
        return (
            ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD)
            .annotate(
                references_count=Count('references', distinct=True),
                weaknesses_count=Count('weaknesses', distinct=True),
                metrics_count=Count('metrics', distinct=True),
                max_metric_score=Max('metrics__base_score'),
            )
            .order_by('-last_modified_at', '-published_at', '-created_at')
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['kb_rules_total'] = safe_query(0, lambda: VulnerabilityRule.objects.count())
        context['nvd_advisories_total'] = safe_query(0, lambda: ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD).count())
        context['nvd_critical_high_total'] = safe_query(
            0,
            lambda: ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD, severity__in=['critical', 'high']).count(),
        )
        context['nvd_last_sync_at'] = safe_query(
            None,
            lambda: AdvisorySyncJob.objects.filter(
                source=ExternalAdvisory.Source.NVD,
                status=AdvisorySyncJob.Status.COMPLETED,
                last_successful_sync_at__isnull=False,
            )
            .order_by('-last_successful_sync_at')
            .values_list('last_successful_sync_at', flat=True)
            .first(),
        )
        context['nvd_sync_jobs'] = safe_query(
            [],
            lambda: list(AdvisorySyncJob.objects.filter(source=ExternalAdvisory.Source.NVD).order_by('-created_at')[:10]),
        )
        return context

    def test_func(self):
        return self.request.user.is_staff


class ScanProfileListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = ScanProfile
    template_name = 'dashboard/scan_profiles_list.html'
