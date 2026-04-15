from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
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
            context.update({'assets_total': 0, 'recent_scans': [], 'findings_by_severity': [], 'open_vs_remediated': [], 'top_services': [], 'top_products': [], 'recent_activity': [], 'kb_rules_total': 0})
            return context

        context['assets_total'] = safe_query(0, lambda: Asset.objects.filter(organization=org).count())
        context['recent_scans'] = safe_query([], lambda: list(ScanExecution.objects.filter(organization=org).order_by('-created_at')[:5]))
        context['findings_by_severity'] = safe_query([], lambda: list(Finding.objects.filter(organization=org).values('severity').annotate(total=Count('id'))))
        context['open_vs_remediated'] = safe_query([], lambda: list(Finding.objects.filter(organization=org).values('status').annotate(total=Count('id')).filter(status__in=['open', 'remediated'])))
        context['top_services'] = safe_query([], lambda: list(ServiceFinding.objects.filter(organization=org).exclude(service='').values('service').annotate(total=Count('id')).order_by('-total')[:5]))
        context['top_products'] = safe_query([], lambda: list(ServiceFinding.objects.filter(organization=org).exclude(product='').values('product').annotate(total=Count('id')).order_by('-total')[:5]))
        context['recent_activity'] = safe_query([], lambda: list(Finding.objects.filter(organization=org).order_by('-created_at')[:8]))
        context['kb_rules_total'] = safe_query(0, lambda: VulnerabilityRule.objects.count())
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


class FindingDetailView(LoginRequiredMixin, TenantQuerysetMixin, DetailView):
    model = Finding
    template_name = 'dashboard/finding_detail.html'


class KnowledgeBaseListView(LoginRequiredMixin, ListView):
    model = VulnerabilityRule
    template_name = 'dashboard/knowledge_base_list.html'


class ScanProfileListView(LoginRequiredMixin, TenantQuerysetMixin, ListView):
    model = ScanProfile
    template_name = 'dashboard/scan_profiles_list.html'
