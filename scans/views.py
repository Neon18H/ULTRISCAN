import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import Http404
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.views.generic import DetailView, ListView, TemplateView, View
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts.permissions import TenantAccessPermission
from accounts.tenancy import TenantQuerysetMixin, get_active_organization
from core.tenant_api import TenantModelViewSetMixin
from dashboard.reports import build_scan_report_pdf

from .forms import (
    CreateScanForm,
    PROFILE_NAME_ALIASES,
    SCAN_TYPE_HELP,
    SCAN_TYPE_TO_PROFILE,
    WEB_APPSEC_MODULE_CHOICES,
    WEB_APPSEC_MODULE_DETAILS,
    WEB_APPSEC_MODULE_GROUPS,
)
from .models import ScanExecution
from .serializers import ScanExecutionSerializer
from .tasks import run_scan_task

logger = logging.getLogger(__name__)


class ScanExecutionViewSet(TenantModelViewSetMixin, viewsets.ModelViewSet):
    queryset = ScanExecution.objects.select_related('asset', 'profile').all()
    serializer_class = ScanExecutionSerializer
    permission_classes = [TenantAccessPermission]

    def perform_create(self, serializer):
        org = self.get_organization()
        asset = serializer.validated_data.get('asset')
        profile = serializer.validated_data.get('profile')
        if asset.organization_id != org.id or profile.organization_id != org.id:
            from rest_framework.exceptions import PermissionDenied

            raise PermissionDenied('Asset/Profile fuera de la organización activa.')
        serializer.save(organization=org, launched_by=self.request.user, status=ScanExecution.Status.PENDING)

    @action(detail=True, methods=['post'])
    def launch(self, request, pk=None):
        scan = self.get_object()
        scan.status = ScanExecution.Status.QUEUED
        scan.progress_percent = 0
        scan.progress_stage = 'queued'
        scan.status_message = 'Escaneo encolado'
        scan.save(update_fields=['status', 'progress_percent', 'progress_stage', 'status_message', 'updated_at'])
        run_scan_task.delay(scan.id)
        return Response({'detail': 'Escaneo encolado'}, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=['post'])
    def archive(self, request, pk=None):
        scan = self.get_object()
        scan.is_archived = True
        scan.archived_at = timezone.now()
        scan.save(update_fields=['is_archived', 'archived_at', 'updated_at'])
        return Response({'detail': f'Escaneo #{scan.id} archivado'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    def unarchive(self, request, pk=None):
        scan = self.get_object()
        scan.is_archived = False
        scan.archived_at = None
        scan.save(update_fields=['is_archived', 'archived_at', 'updated_at'])
        return Response({'detail': f'Escaneo #{scan.id} reactivado'}, status=status.HTTP_200_OK)


class ScanCreateView(LoginRequiredMixin, TemplateView):
    template_name = 'scans/create.html'

    def _get_org(self):
        org = get_active_organization(self.request.user)
        if not org:
            raise PermissionDenied('No existe una organización activa para este usuario.')
        return org

    def _build_form(self, org, post_data=None):
        asset_id = self.request.GET.get('asset')
        initial_asset = None
        if asset_id and str(asset_id).isdigit():
            initial_asset = int(asset_id)
        return CreateScanForm(post_data, organization=org, initial_asset=initial_asset)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        org = self._get_org()
        form = kwargs.get('form') or self._build_form(org)
        module_labels = dict(WEB_APPSEC_MODULE_CHOICES)
        grouped_modules = []
        selected_modules = form['web_appsec_modules'].value() or []
        if isinstance(selected_modules, str):
            selected_modules = [selected_modules]
        for group in WEB_APPSEC_MODULE_GROUPS:
            modules = []
            for module_key in group.get('modules', []):
                if module_key not in module_labels:
                    continue
                module_details = WEB_APPSEC_MODULE_DETAILS.get(module_key, {})
                modules.append(
                    {
                        'key': module_key,
                        'label': module_labels[module_key],
                        'description': module_details.get('description', ''),
                        'tool': module_details.get('tool', 'N/A'),
                        'impact': module_details.get('impact', ''),
                        'severity': module_details.get('severity', 'medium'),
                    }
                )
            if modules:
                grouped_modules.append(
                    {
                        'id': group.get('id', ''),
                        'name': group.get('name', ''),
                        'icon': group.get('icon', 'bi-grid'),
                        'modules': modules,
                    }
                )
        context['form'] = form
        context['scan_type_help'] = SCAN_TYPE_HELP
        context['web_appsec_module_groups'] = grouped_modules
        context['web_appsec_all_modules'] = [key for key, _ in WEB_APPSEC_MODULE_CHOICES]
        context['selected_web_appsec_modules'] = selected_modules
        return context

    def post(self, request, *args, **kwargs):
        org = self._get_org()
        form = self._build_form(org, request.POST)
        if not form.is_valid():
            messages.error(request, 'Revisa los campos del formulario para continuar.')
            return self.render_to_response(self.get_context_data(form=form))

        asset = form.cleaned_data['asset']
        profile = form.cleaned_data['profile']
        scan_type = form.cleaned_data['scan_type']
        expected_profile = SCAN_TYPE_TO_PROFILE.get(scan_type)
        expected_profile_names = PROFILE_NAME_ALIASES.get(expected_profile, {expected_profile}) if expected_profile else set()
        if expected_profile and profile.name.lower() not in expected_profile_names:
            messages.error(request, f'El tipo seleccionado requiere el perfil {expected_profile}.')
            return self.render_to_response(self.get_context_data(form=form))

        appsec_configuration = {
            'aggressiveness': form.cleaned_data.get('web_appsec_aggressiveness') or 'medium',
            'modules': form.cleaned_data.get('web_appsec_modules') or [],
            'controls': {
                'rate_limit': form.cleaned_data.get('web_rate_limit'),
                'concurrency': form.cleaned_data.get('web_concurrency'),
                'max_depth': form.cleaned_data.get('web_max_depth'),
                'max_endpoints': form.cleaned_data.get('web_max_endpoints'),
                'module_timeout': form.cleaned_data.get('web_module_timeout'),
                'exclude_paths': CreateScanForm.parse_csv_field(form.cleaned_data.get('web_excluded_paths')),
                'allowlist_domains': CreateScanForm.parse_csv_field(form.cleaned_data.get('web_allowlist_domains')),
                'authenticated_mode': bool(form.cleaned_data.get('web_authenticated_mode')),
            },
        }

        scan = ScanExecution.objects.create(
            organization=org,
            asset=asset,
            profile=profile,
            launched_by=request.user,
            status=ScanExecution.Status.QUEUED,
            progress_percent=0,
            progress_stage='queued',
            status_message='Escaneo en cola',
            engine_metadata={
                'requested_scan_type': scan_type,
                'requested_module': form.cleaned_data['module'],
                'requested_options': form.cleaned_data['options'],
                'web_appsec': appsec_configuration,
            },
        )
        run_scan_task.delay(scan.id)
        messages.success(request, f'Escaneo #{scan.id} encolado correctamente.')
        return redirect(reverse('scans-detail', kwargs={'pk': scan.id}))


class ScanListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = ScanExecution
    template_name = 'scans/list.html'
    paginate_by = 25

    def get_queryset(self):
        queryset = super().get_queryset().select_related('asset', 'profile', 'organization')

        scan_id = (self.request.GET.get('scan_id') or '').strip()
        asset = (self.request.GET.get('asset') or '').strip()
        scan_type = (self.request.GET.get('scan_type') or '').strip()
        profile = (self.request.GET.get('profile') or '').strip()
        status_value = (self.request.GET.get('status') or '').strip()
        archived = (self.request.GET.get('archived') or 'active').strip()
        date_from = (self.request.GET.get('date_from') or '').strip()
        date_to = (self.request.GET.get('date_to') or '').strip()
        organization = (self.request.GET.get('organization') or '').strip()
        ordering = (self.request.GET.get('ordering') or '-created_at').strip()

        if scan_id:
            queryset = queryset.filter(id=scan_id) if scan_id.isdigit() else queryset.none()
        if asset:
            queryset = queryset.filter(Q(asset__name__icontains=asset) | Q(asset__value__icontains=asset))
        if scan_type:
            queryset = queryset.filter(engine_metadata__requested_scan_type=scan_type)
        if profile:
            queryset = queryset.filter(profile__name=profile)
        if status_value:
            queryset = queryset.filter(status=status_value)
        if date_from:
            queryset = queryset.filter(created_at__date__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__date__lte=date_to)
        if organization:
            queryset = queryset.filter(organization__name=organization)
        if archived == 'active':
            queryset = queryset.filter(is_archived=False)
        elif archived == 'archived':
            queryset = queryset.filter(is_archived=True)

        ordering_map = {
            'date_desc': '-created_at',
            'date_asc': 'created_at',
            'status_asc': 'status',
            'status_desc': '-status',
            'duration_desc': '-duration_seconds',
            'duration_asc': 'duration_seconds',
            '-created_at': '-created_at',
            'created_at': 'created_at',
        }
        return queryset.order_by(ordering_map.get(ordering, '-created_at'))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        base_queryset = super().get_queryset().select_related('profile', 'organization')
        context['status_choices'] = ScanExecution.Status.choices
        context['profiles'] = base_queryset.values_list('profile__name', flat=True).distinct().order_by('profile__name')
        context['scan_types'] = sorted(
            {
                (row or 'nmap_discovery')
                for row in base_queryset.values_list('engine_metadata__requested_scan_type', flat=True)
            }
        )
        context['organizations'] = base_queryset.values_list('organization__name', flat=True).distinct().order_by('organization__name')
        context['archive_choices'] = (
            ('active', 'Activos'),
            ('archived', 'Archivados'),
            ('all', 'Todos'),
        )
        context['current_ordering'] = (self.request.GET.get('ordering') or 'date_desc').strip()
        return context


class ScanArchiveToggleView(LoginRequiredMixin, TenantQuerysetMixin, View):
    archive = True

    def post(self, request, *args, **kwargs):
        scan = self.get_queryset().filter(pk=kwargs.get('pk')).first()
        if not scan:
            raise Http404('Scan no encontrado')
        scan.is_archived = self.archive
        scan.archived_at = timezone.now() if self.archive else None
        scan.save(update_fields=['is_archived', 'archived_at', 'updated_at'])
        action = 'archivado' if self.archive else 'restaurado'
        messages.success(request, f'Scan #{scan.id} {action} correctamente.')
        return redirect(f"{reverse('scans-list')}?{request.GET.urlencode()}") if request.GET else redirect('scans-list')


class ScanArchiveView(ScanArchiveToggleView):
    archive = True


class ScanUnarchiveView(ScanArchiveToggleView):
    archive = False


class ScanDetailView(LoginRequiredMixin, TenantQuerysetMixin, DetailView):
    model = ScanExecution
    template_name = 'scans/detail.html'

    @staticmethod
    def _as_dict(value):
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _as_list(value):
        return value if isinstance(value, list) else []

    def _normalize_scan_results(self):
        summary = self._as_dict(self.object.summary)
        engine_metadata = self._as_dict(self.object.engine_metadata)
        if not isinstance(self.object.summary, dict):
            logger.warning('Scan %s has non-dict summary payload. Falling back to empty dict.', self.object.id)
        if not isinstance(self.object.engine_metadata, dict):
            logger.warning('Scan %s has non-dict engine_metadata payload. Falling back to empty dict.', self.object.id)
        structured_results = self._as_dict(engine_metadata.get('structured_results'))
        scan_category = structured_results.get('category') or summary.get('category') or engine_metadata.get('pipeline') or 'infra'
        tools = self._as_dict(structured_results.get('tools'))
        modules = self._as_dict(engine_metadata.get('modules'))

        warnings = self._as_list(structured_results.get('warnings'))
        if not warnings:
            warnings = self._as_list(summary.get('warnings'))

        interpreted_headers = self._as_list(structured_results.get('interpreted_headers'))
        dependencies = self._as_dict(tools.get('dependency_checks'))
        if not dependencies:
            dependencies = self._as_dict(structured_results.get('dependency_checks'))
        if not dependencies:
            dependencies = self._as_dict(summary.get('dependency_checks'))

        available_tools = self._as_list(tools.get('available'))
        executed_tools = self._as_list(tools.get('executed'))
        omitted_tools = self._as_list(tools.get('skipped'))

        if not available_tools:
            available_tools = self._as_list(summary.get('tools_available'))
        if not executed_tools:
            executed_tools = self._as_list(structured_results.get('tools_executed')) or self._as_list(summary.get('tools_executed'))
        if not omitted_tools:
            omitted_tools = self._as_list(structured_results.get('tools_skipped'))

        protections_present = [row for row in interpreted_headers if isinstance(row, dict) and row.get('status') == 'OK']
        protections_absent = [
            row
            for row in interpreted_headers
            if isinstance(row, dict)
            and row.get('status') == 'WARNING'
            and row.get('header') not in {'server', 'x-powered-by'}
        ]
        exposure_findings = [
            row
            for row in interpreted_headers
            if isinstance(row, dict)
            and row.get('header') in {'server', 'x-powered-by'}
            and row.get('status') == 'WARNING'
        ]
        informational_findings = [
            row for row in interpreted_headers if isinstance(row, dict) and row.get('status') == 'INFO'
        ]

        technologies = self._as_list(structured_results.get('technologies'))
        endpoints = self._as_list(structured_results.get('endpoints'))
        vulnerabilities = self._as_list(structured_results.get('vulnerabilities'))
        http_headers = self._as_dict(structured_results.get('headers'))
        metadata = self._as_dict(structured_results.get('metadata'))
        redirects = self._as_list(structured_results.get('redirects'))
        web_basic_findings = self._as_list(structured_results.get('web_findings_basic'))
        web_findings = self._as_list(structured_results.get('web_findings'))
        web_kpis = self._as_dict(structured_results.get('web_kpis'))
        vulnerabilities_by_severity = self._as_dict(structured_results.get('vulnerabilities_by_severity'))
        endpoints_by_source = self._as_dict(structured_results.get('endpoints_by_source'))
        deduped_evidences = self._dedupe_evidences()
        deduped_findings = self._dedupe_findings()
        service_findings = list(self.object.service_findings.all())
        open_ports = sorted({service.port for service in service_findings if service.port})
        services_by_name = {}
        for service in service_findings:
            key = service.service or 'unknown'
            services_by_name[key] = services_by_name.get(key, 0) + 1
        top_services = sorted(services_by_name.items(), key=lambda row: (-row[1], row[0]))[:8]
        versions_detected = sorted(
            {
                f"{service.product} {service.normalized_version or service.raw_version}".strip()
                for service in service_findings
                if service.product or service.normalized_version or service.raw_version
            }
        )
        infra_kpis = {
            'open_ports': len(open_ports),
            'services_detected': len(service_findings),
            'products_detected': len({service.product for service in service_findings if service.product}),
            'versions_detected': len(versions_detected),
            'findings_detected': len(deduped_findings),
        }
        headers_analysis = {
            'present': protections_present,
            'absent': protections_absent,
            'exposure': exposure_findings,
            'informational': informational_findings,
            'summary': {
                'present': len(protections_present),
                'absent': len(protections_absent),
                'informational': len(informational_findings) + len(exposure_findings),
            },
        }
        if not web_kpis:
            web_kpis = {
                'technologies_detected': len(technologies),
                'endpoints_discovered': len(endpoints),
                'vulnerabilities_detected': len(vulnerabilities),
                'web_basic_findings': len(web_basic_findings),
                'controls_present': headers_analysis['summary']['present'],
                'controls_absent': headers_analysis['summary']['absent'],
                'severity_aggregate': vulnerabilities_by_severity,
                'score': max(0, 100 - (len(vulnerabilities) * 5)),
                'kpi_blocks': [],
            }
        if not web_findings:
            web_findings = web_basic_findings

        return {
            'summary': summary,
            'scan_category': scan_category,
            'engine_metadata': engine_metadata,
            'structured_results': structured_results,
            'tools': tools,
            'warnings': warnings,
            'modules': modules,
            'available_tools': available_tools,
            'executed_tools': executed_tools,
            'omitted_tools': omitted_tools,
            'dependencies': dependencies,
            'headers_analysis': headers_analysis,
            'interpreted_headers': interpreted_headers,
            'technologies': technologies,
            'endpoints': endpoints,
            'vulnerabilities': vulnerabilities,
            'fingerprint': structured_results.get('fingerprint') or {},
            'cms': structured_results.get('cms') or '',
            'http_headers': http_headers,
            'metadata': metadata,
            'redirects': redirects,
            'web_basic_findings': web_basic_findings,
            'web_findings': web_findings,
            'web_kpis': web_kpis,
            'vulnerabilities_by_severity': vulnerabilities_by_severity,
            'endpoints_by_source': endpoints_by_source,
            'deduped_evidences': deduped_evidences,
            'deduped_findings': deduped_findings,
            'status_label': self._build_status_label(summary),
            'service_findings': service_findings,
            'open_ports': open_ports,
            'top_services': top_services,
            'versions_detected': versions_detected,
            'infra_kpis': infra_kpis,
        }

    def _dedupe_findings(self):
        deduped = []
        seen = set()
        for finding in self.object.findings.all():
            key = (finding.title.strip().lower(), finding.severity, finding.status)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    def _dedupe_evidences(self):
        deduped = []
        seen = set()
        for evidence in self.object.raw_evidences.all():
            payload = evidence.payload if isinstance(evidence.payload, dict) else {}
            key = (
                evidence.source.strip().lower(),
                evidence.host.strip().lower(),
                str(payload.get('endpoints') or payload.get('vulnerabilities') or payload)[:200],
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(evidence)
        return deduped

    def _build_status_label(self, summary):
        if self.object.status in {ScanExecution.Status.QUEUED, ScanExecution.Status.RUNNING}:
            return self.object.get_status_display()
        if self.object.status == ScanExecution.Status.FAILED:
            return 'Failed'
        if summary.get('partial_result'):
            return 'Partial'
        if self.object.status == ScanExecution.Status.COMPLETED:
            return 'Completed'
        return self.object.get_status_display()

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .select_related('asset', 'profile', 'launched_by')
            .prefetch_related('service_findings', 'web_findings', 'raw_evidences', 'findings')
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(self._normalize_scan_results())
        return context


class ScanReportPdfView(LoginRequiredMixin, TenantQuerysetMixin, View):
    def get(self, request, *args, **kwargs):
        scan = (
            ScanExecution.objects.select_related('asset', 'profile', 'launched_by')
            .prefetch_related('findings')
            .filter(organization=get_active_organization(request.user), pk=kwargs.get('pk'))
            .first()
        )
        if not scan:
            raise Http404('Scan no encontrado.')
        return build_scan_report_pdf(scan=scan, generated_by=request.user)
