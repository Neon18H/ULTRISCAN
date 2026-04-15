from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import FormView, TemplateView

from .forms import EmailAuthenticationForm, MembershipRoleForm, RegistrationForm, TeamMemberCreateForm
from .models import OrganizationMembership
from .tenancy import OrganizationRolePermissionMixin, get_active_membership


class AccountLoginView(LoginView):
    form_class = EmailAuthenticationForm
    template_name = 'auth/login.html'
    redirect_authenticated_user = True


class AccountLogoutView(LogoutView):
    next_page = reverse_lazy('login')

    def post(self, request, *args, **kwargs):
        messages.info(request, 'Sesión cerrada correctamente.')
        return super().post(request, *args, **kwargs)


class RegisterView(FormView):
    template_name = 'auth/register.html'
    form_class = RegistrationForm
    success_url = reverse_lazy('dashboard-home')

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        messages.success(self.request, 'Cuenta y organización creadas correctamente.')
        return super().form_valid(form)


class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = 'account/profile.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['membership'] = get_active_membership(self.request.user)
        return context


class OrganizationSettingsView(LoginRequiredMixin, OrganizationRolePermissionMixin, TemplateView):
    template_name = 'account/organization_settings.html'

    def post(self, request, *args, **kwargs):
        membership = get_active_membership(self.request.user)
        if not membership:
            return HttpResponseForbidden('Sin membresía activa.')
        if not self.user_can_manage_organization():
            return HttpResponseForbidden('No tienes permisos para gestionar organización.')
        name = request.POST.get('name', '').strip()
        if name:
            membership.organization.name = name
            membership.organization.save(update_fields=['name'])
            messages.success(request, 'Nombre de organización actualizado.')
        return redirect('organization-settings')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['membership'] = get_active_membership(self.request.user)
        return context


class TeamManagementView(LoginRequiredMixin, OrganizationRolePermissionMixin, TemplateView):
    template_name = 'account/team.html'

    def dispatch(self, request, *args, **kwargs):
        if not self.user_can_manage_organization():
            return HttpResponseForbidden('No tienes permisos para administrar miembros.')
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        membership = get_active_membership(self.request.user)
        org = membership.organization
        context['organization'] = org
        context['memberships'] = org.memberships.select_related('user').all()
        context['create_form'] = TeamMemberCreateForm(organization=org)
        return context

    def post(self, request, *args, **kwargs):
        membership = get_active_membership(self.request.user)
        org = membership.organization
        action = request.POST.get('action')
        if action == 'create':
            form = TeamMemberCreateForm(request.POST, organization=org)
            if form.is_valid():
                form.save()
                messages.success(request, 'Miembro agregado/actualizado correctamente.')
            else:
                messages.error(request, 'No se pudo agregar el miembro. Revisa el formulario.')
        elif action == 'update_role':
            item = get_object_or_404(OrganizationMembership, id=request.POST.get('membership_id'), organization=org)
            role_form = MembershipRoleForm(request.POST, instance=item)
            if role_form.is_valid():
                role_form.save()
                messages.success(request, 'Rol actualizado correctamente.')
            else:
                messages.error(request, 'No se pudo actualizar el rol.')
        return redirect('team-management')
