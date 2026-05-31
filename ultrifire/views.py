import json

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views import View

from accounts.tenancy import get_active_organization
from .forms import PolicyForm
from .models import ProviderArtifact
from .providers import PROVIDER_CATALOG, get_provider
from .services import (
    PolicyValidationError,
    apply_policy,
    create_policy,
    disable_policy,
    get_policy,
    list_policies,
    preview_policy,
    handle_command,
)


class PolicyListView(LoginRequiredMixin, View):
    template_name = 'ultrifire/policies.html'

    def get(self, request):
        org = get_active_organization(request.user)
        policies = list_policies(org) if org else []
        preview = request.session.pop('ultrifire_preview', None)
        apply_result = request.session.pop('ultrifire_apply_result', None)
        return render(request, self.template_name, self._context(request, org, policies, PolicyForm(organization=org), preview=preview, apply_result=apply_result))

    def post(self, request):
        org = get_active_organization(request.user)
        form = PolicyForm(request.POST, organization=org)
        if not org:
            messages.error(request, 'No tienes una organización activa.')
            return redirect('ultrifire-policies')
        if form.is_valid():
            result = create_policy(form.normalized_policy, organization=org, safe_mode=True)
            if result['ok']:
                messages.success(request, 'Política UltriFire creada en safe mode. No se aplicaron cambios reales.')
                return redirect('ultrifire-policies')
            messages.error(request, result.get('error', 'No se pudo crear la política.'))
        policies = list_policies(org)
        return render(request, self.template_name, self._context(request, org, policies, form))

    def _context(self, request, org, policies, form, preview=None, apply_result=None):
        for policy in policies:
            policy['provider_meta'] = get_provider(policy.get('provider'))
        return {
            'form': form,
            'policies': policies,
            'providers': PROVIDER_CATALOG,
            'preview': preview,
            'apply_result': apply_result,
            'safe_mode': True,
            'cloud_resources': list(ProviderArtifact.objects.filter(organization=org).values('id', 'provider', 'resource_name', 'resource_type', 'region', 'private_ip', 'public_ip')) if org else [],
        }


class PolicyActionView(LoginRequiredMixin, View):
    def post(self, request, policy_id, action):
        org = get_active_organization(request.user)
        try:
            if action == 'disable':
                disable_policy(policy_id, organization=org)
                messages.success(request, 'Política deshabilitada.')
            elif action == 'apply':
                result = apply_policy(policy_id, organization=org, safe_mode=True)
                messages.warning(request, result['message'])
                request.session['ultrifire_apply_result'] = result
            elif action == 'preview':
                policy = get_policy(policy_id, organization=org)
                request.session['ultrifire_preview'] = {'policy': policy, 'preview': preview_policy(policy)}
            else:
                messages.error(request, 'Acción no soportada.')
        except PolicyValidationError as exc:
            messages.error(request, str(exc))
        return redirect('ultrifire-policies')


class PolicyPreviewView(LoginRequiredMixin, View):
    def get(self, request, policy_id):
        org = get_active_organization(request.user)
        policy = get_policy(policy_id, organization=org)
        return JsonResponse({'ok': True, 'policy': policy, 'preview': preview_policy(policy)})


class FirewallCommandView(LoginRequiredMixin, View):
    def post(self, request):
        org = get_active_organization(request.user)
        try:
            body = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'ok': False, 'error': 'JSON inválido.'}, status=400)
        result = handle_command(
            body.get('command_type') or body.get('type'),
            body.get('payload') or {},
            organization=org,
            safe_mode=body.get('safe_mode', True),
        )
        return JsonResponse(result, status=200 if result.get('ok') else 400)
