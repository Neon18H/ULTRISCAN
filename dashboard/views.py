from django.contrib import messages
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from django.core.exceptions import PermissionDenied
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.mixins import UserPassesTestMixin
from django.db import OperationalError, ProgrammingError
from django.db.models import Count, Max, Q
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.views.generic import CreateView, DetailView, ListView, TemplateView, UpdateView, View

from accounts.tenancy import TenantQuerysetMixin, get_active_membership, get_active_organization
from assets.models import Asset
from findings.models import Finding
from findings.nvd_correlation import FindingNvdCorrelationService
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

    @staticmethod
    def _as_dict(value):
        return value if isinstance(value, dict) else {}

    def _build_correlation_context(self, matched_rule):
        trace = self._as_dict(self.object.correlation_trace)
        detected_product = self._as_dict(trace.get('detected_product'))
        detected_version = self._as_dict(trace.get('detected_version'))
        source_evidence = self._as_dict(trace.get('source_evidence'))

        service_finding = self.object.service_finding
        raw_evidence = self.object.raw_evidence

        match_reasons = trace.get('match_reasons')
        if isinstance(match_reasons, (list, tuple)):
            correlation_reason = ', '.join(str(item) for item in match_reasons if item)
        elif match_reasons:
            correlation_reason = str(match_reasons)
        else:
            correlation_reason = ''

        return {
            'detected_product': (
                detected_product.get('normalized_product')
                or detected_product.get('product')
                or getattr(service_finding, 'normalized_product', '')
                or getattr(service_finding, 'product', '')
            ),
            'normalized_product': (
                detected_product.get('normalized_product')
                or getattr(service_finding, 'normalized_product', '')
            ),
            'raw_product': (
                detected_product.get('product')
                or getattr(service_finding, 'product', '')
            ),
            'detected_version': (
                detected_version.get('version_used_for_matching')
                or detected_version.get('normalized_version')
                or getattr(service_finding, 'raw_version', '')
                or getattr(service_finding, 'version', '')
            ),
            'raw_version': (
                detected_version.get('raw_version')
                or getattr(service_finding, 'raw_version', '')
                or getattr(service_finding, 'version', '')
            ),
            'normalized_version': (
                detected_version.get('normalized_version')
                or getattr(service_finding, 'normalized_version', '')
            ),
            'matched_rule': trace.get('rule_title') or getattr(matched_rule, 'title', ''),
            'matched_rule_type': trace.get('rule_type') or '',
            'correlation_reason': correlation_reason,
            'detected_cpe': detected_product.get('detected_cpe') or '',
            'family_aliases': detected_product.get('family_aliases') or [],
            'evidence_source': (
                source_evidence.get('source')
                or getattr(raw_evidence, 'source', '')
                or 'Service finding'
            ),
            'evidence_host': source_evidence.get('host') or getattr(service_finding, 'host', ''),
            'evidence_service': source_evidence.get('service') or getattr(service_finding, 'service', ''),
            'evidence_port': source_evidence.get('port') or getattr(service_finding, 'port', ''),
            'has_detailed_context': bool(trace),
        }

    def get_queryset(self):
        organization = get_active_organization(self.request.user)
        if not organization:
            raise PermissionDenied('No existe una organización activa para este usuario.')
        return (
            Finding.objects.filter(organization=organization)
            .select_related(
                'asset',
                'scan_execution',
                'service_finding',
                'raw_evidence',
                'vulnerability_rule',
                'misconfiguration_rule',
                'end_of_life_rule',
            )
            .order_by('-created_at')
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        matched_rule = self.object.vulnerability_rule or self.object.misconfiguration_rule or self.object.end_of_life_rule
        context['matched_rule'] = matched_rule
        context['matched_rule_type'] = (
            'Vulnerability'
            if self.object.vulnerability_rule
            else 'Misconfiguration'
            if self.object.misconfiguration_rule
            else 'End-of-Life'
            if self.object.end_of_life_rule
            else 'Unknown'
        )
        context['correlation_context'] = self._build_correlation_context(matched_rule)
        context['nvd_correlation'] = safe_query(
            FindingNvdCorrelationService()._no_match_payload(self.object),
            lambda: FindingNvdCorrelationService().correlate(self.object),
        )
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

    severity_values = {'critical', 'high', 'medium', 'low', 'info'}

    def get_queryset(self):
        queryset = (
            ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD)
            .annotate(
                references_count=Count('references', distinct=True),
                weaknesses_count=Count('weaknesses', distinct=True),
                metrics_count=Count('metrics', distinct=True),
                max_metric_score=Max('metrics__base_score'),
            )
            .order_by('-last_modified_at', '-published_at', '-created_at')
        )
        return self.apply_filters(queryset)

    def apply_filters(self, queryset):
        params = self.request.GET

        severity = params.get('severity', '').strip().lower()
        if severity in self.severity_values:
            queryset = queryset.filter(severity=severity)

        cve_id = params.get('cve_id', '').strip().upper()
        if cve_id:
            queryset = queryset.filter(cve_id__icontains=cve_id)

        description = params.get('description', '').strip()
        if description:
            queryset = queryset.filter(description__icontains=description)

        published_from = params.get('published_from', '').strip()
        if published_from:
            queryset = queryset.filter(published_at__date__gte=published_from)

        published_to = params.get('published_to', '').strip()
        if published_to:
            queryset = queryset.filter(published_at__date__lte=published_to)

        modified_from = params.get('modified_from', '').strip()
        if modified_from:
            queryset = queryset.filter(last_modified_at__date__gte=modified_from)

        modified_to = params.get('modified_to', '').strip()
        if modified_to:
            queryset = queryset.filter(last_modified_at__date__lte=modified_to)

        score_min = self._parse_score(params.get('score_min'))
        if score_min is not None:
            queryset = queryset.filter(Q(cvss_score__gte=score_min) | Q(max_metric_score__gte=score_min))

        score_max = self._parse_score(params.get('score_max'))
        if score_max is not None:
            queryset = queryset.filter(Q(cvss_score__lte=score_max) | Q(max_metric_score__lte=score_max))

        has_kev = params.get('has_kev', '').strip().lower()
        if has_kev in {'true', '1', 'yes'}:
            queryset = queryset.filter(has_kev=True)
        elif has_kev in {'false', '0', 'no'}:
            queryset = queryset.filter(has_kev=False)

        return queryset

    def _parse_score(self, value):
        if not value:
            return None
        try:
            parsed = Decimal(str(value).strip())
        except (InvalidOperation, ValueError):
            return None
        return max(Decimal('0.0'), min(Decimal('10.0'), parsed))

    def get_active_filter_chips(self):
        labels = {
            'severity': 'Severity',
            'cve_id': 'CVE ID',
            'description': 'Description',
            'published_from': 'Published from',
            'published_to': 'Published to',
            'modified_from': 'Modified from',
            'modified_to': 'Modified to',
            'score_min': 'CVSS min',
            'score_max': 'CVSS max',
            'has_kev': 'Has KEV',
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

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        base_query = ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD)
        context['kb_rules_total'] = safe_query(0, lambda: VulnerabilityRule.objects.count())
        context['nvd_advisories_total'] = safe_query(0, lambda: base_query.count())
        context['nvd_critical_total'] = safe_query(0, lambda: base_query.filter(severity='critical').count())
        context['nvd_high_total'] = safe_query(0, lambda: base_query.filter(severity='high').count())
        context['nvd_medium_total'] = safe_query(0, lambda: base_query.filter(severity='medium').count())
        context['nvd_low_total'] = safe_query(0, lambda: base_query.filter(severity='low').count())
        context['nvd_info_total'] = safe_query(0, lambda: base_query.filter(severity='info').count())
        context['nvd_kev_total'] = safe_query(0, lambda: base_query.filter(has_kev=True).count())
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
        context['severity_distribution'] = self._build_severity_distribution(base_query)
        context['top_technologies'] = self._build_top_technologies()
        context['recent_advisories'] = safe_query(
            [],
            lambda: list(
                base_query.order_by('-last_modified_at', '-published_at')[:8]
            ),
        )
        context['active_filter_chips'] = self.get_active_filter_chips()
        context['result_count'] = self.object_list.count()
        context['current_querystring'] = self.get_querystring_without_page()
        return context

    def _build_severity_distribution(self, base_query):
        rows = safe_query([], lambda: list(base_query.values('severity').annotate(total=Count('id'))))
        total = sum(row['total'] for row in rows) or 1
        order = ['critical', 'high', 'medium', 'low', 'info']
        lookup = {row['severity']: row['total'] for row in rows}
        return [
            {
                'severity': sev,
                'total': lookup.get(sev, 0),
                'percentage': round((lookup.get(sev, 0) / total) * 100, 1),
            }
            for sev in order
        ]

    def _build_top_technologies(self):
        cpe_rows = safe_query(
            [],
            lambda: list(
                ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD)
                .values('id', 'last_modified_at', 'severity', 'cpe_matches__criteria')
            ),
        )
        technology_bucket: dict[str, dict] = {}
        for row in cpe_rows:
            criteria = row.get('cpe_matches__criteria') or ''
            parts = criteria.split(':')
            if len(parts) < 6:
                continue
            vendor = (parts[3] or '').replace('_', ' ').strip()
            product = (parts[4] or '').replace('_', ' ').strip()
            if not product:
                continue
            label = f'{vendor} {product}'.strip()
            item = technology_bucket.setdefault(
                label,
                {
                    'technology': label,
                    'count': 0,
                    'critical_high': 0,
                    'last_modified_at': row.get('last_modified_at'),
                    'advisory_ids': set(),
                },
            )
            advisory_id = row['id']
            if advisory_id in item['advisory_ids']:
                continue
            item['advisory_ids'].add(advisory_id)
            item['count'] += 1
            if row.get('severity') in {'critical', 'high'}:
                item['critical_high'] += 1
            if row.get('last_modified_at') and (
                not item['last_modified_at'] or row['last_modified_at'] > item['last_modified_at']
            ):
                item['last_modified_at'] = row['last_modified_at']
        ranked = sorted(technology_bucket.values(), key=lambda x: x['count'], reverse=True)[:10]
        return ranked

    def test_func(self):
        if self.request.user.is_staff:
            return True
        membership = get_active_membership(self.request.user)
        if not membership:
            return False
        return membership.role in {'owner', 'admin'}


class KnowledgeBaseDetailView(LoginRequiredMixin, UserPassesTestMixin, DetailView):
    model = ExternalAdvisory
    template_name = 'dashboard/knowledge_base_detail.html'
    slug_field = 'cve_id'
    slug_url_kwarg = 'cve_id'

    def get_queryset(self):
        return (
            ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD)
            .prefetch_related('references', 'weaknesses', 'metrics', 'cpe_matches')
            .order_by('-last_modified_at')
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        technology_labels = []
        for cpe in self.object.cpe_matches.all():
            parts = cpe.criteria.split(':')
            if len(parts) < 6:
                continue
            vendor = (parts[3] or '').replace('_', ' ').strip()
            product = (parts[4] or '').replace('_', ' ').strip()
            if product:
                technology_labels.append(f'{vendor} {product}'.strip())
        context['technology_labels'] = sorted(set(technology_labels))
        return context

    def test_func(self):
        if self.request.user.is_staff:
            return True
        membership = get_active_membership(self.request.user)
        if not membership:
            return False
        return membership.role in {'owner', 'admin'}


class ScanProfileListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = ScanProfile
    template_name = 'dashboard/scan_profiles_list.html'
