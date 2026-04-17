from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import DetailView, ListView, TemplateView
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts.permissions import TenantAccessPermission
from accounts.tenancy import TenantQuerysetMixin, get_active_organization
from core.tenant_api import TenantModelViewSetMixin

from .forms import CreateScanForm, SCAN_TYPE_HELP, SCAN_TYPE_TO_PROFILE
from .models import ScanExecution
from .serializers import ScanExecutionSerializer
from .tasks import run_scan_task


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
        scan.save(update_fields=['status', 'updated_at'])
        run_scan_task.delay(scan.id)
        return Response({'detail': 'Escaneo encolado'}, status=status.HTTP_202_ACCEPTED)


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
        context['form'] = form
        context['scan_type_help'] = SCAN_TYPE_HELP
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
        if profile.name.lower() != expected_profile:
            messages.error(request, f'El tipo seleccionado requiere el perfil {expected_profile}.')
            return self.render_to_response(self.get_context_data(form=form))

        scan = ScanExecution.objects.create(
            organization=org,
            asset=asset,
            profile=profile,
            launched_by=request.user,
            status=ScanExecution.Status.QUEUED,
            engine_metadata={
                'requested_scan_type': scan_type,
                'requested_module': form.cleaned_data['module'],
                'requested_options': form.cleaned_data['options'],
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
        return (
            super()
            .get_queryset()
            .select_related('asset', 'profile')
            .order_by('-created_at')
        )


class ScanDetailView(LoginRequiredMixin, TenantQuerysetMixin, DetailView):
    model = ScanExecution
    template_name = 'scans/detail.html'

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .select_related('asset', 'profile', 'launched_by')
            .prefetch_related('service_findings', 'web_findings', 'raw_evidences', 'findings')
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        engine_metadata = self.object.engine_metadata if isinstance(self.object.engine_metadata, dict) else {}
        structured_results = engine_metadata.get('structured_results') if isinstance(engine_metadata, dict) else {}
        if not isinstance(structured_results, dict):
            structured_results = {}
        modules = engine_metadata.get('modules') if isinstance(engine_metadata.get('modules'), dict) else {}
        tools = structured_results.get('tools') if isinstance(structured_results.get('tools'), dict) else {}
        interpreted_headers = (
            structured_results.get('interpreted_headers')
            if isinstance(structured_results.get('interpreted_headers'), list)
            else []
        )
        warnings = structured_results.get('warnings')
        if not isinstance(warnings, list):
            warnings = self.object.summary.get('warnings', []) if isinstance(self.object.summary, dict) else []
        dependencies = tools.get('dependency_checks')
        if not isinstance(dependencies, dict):
            dependencies = structured_results.get('dependency_checks')
        if not isinstance(dependencies, dict):
            dependencies = self.object.summary.get('dependency_checks', {}) if isinstance(self.object.summary, dict) else {}

        protections_present = [row for row in interpreted_headers if row.get('status') == 'OK']
        protections_absent = [
            row
            for row in interpreted_headers
            if row.get('status') == 'WARNING' and row.get('header') not in {'server', 'x-powered-by'}
        ]
        exposure_findings = [
            row
            for row in interpreted_headers
            if row.get('header') in {'server', 'x-powered-by'} and row.get('status') == 'WARNING'
        ]
        informational_findings = [row for row in interpreted_headers if row.get('status') == 'INFO']

        context['structured_results'] = structured_results
        context['tools'] = tools
        context['modules'] = modules
        context['warnings'] = warnings
        context['headers_analysis'] = {
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
        context['dependencies'] = dependencies
        context['executed_tools'] = tools.get('executed') or structured_results.get('tools_executed') or []
        context['omitted_tools'] = tools.get('skipped') or structured_results.get('tools_skipped') or []
        context['interpreted_headers'] = interpreted_headers
        return context
