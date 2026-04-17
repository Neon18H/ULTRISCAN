from django.core.exceptions import PermissionDenied

from .models import OrganizationMembership


def get_active_membership(user):
    if not user or not user.is_authenticated:
        return None
    return user.organization_memberships.select_related('organization').filter(is_active=True).order_by('created_at').first()


def get_active_organization(user):
    membership = get_active_membership(user)
    return membership.organization if membership else None


def user_role_in_org(user):
    membership = get_active_membership(user)
    return membership.role if membership else None


def ensure_same_organization(user, obj):
    org = get_active_organization(user)
    if not org:
        raise PermissionDenied('El usuario no tiene organización activa.')
    if getattr(obj, 'organization_id', None) != org.id:
        raise PermissionDenied('No autorizado para acceder a este recurso.')


class TenantQuerysetMixin:
    organization_field = 'organization'

    def get_organization(self):
        org = get_active_organization(self.request.user)
        if not org:
            raise PermissionDenied('No existe una organización activa para este usuario.')
        return org

    def get_queryset(self):
        queryset_getter = getattr(super(), 'get_queryset', None)
        if callable(queryset_getter):
            queryset = queryset_getter()
        elif getattr(self, 'queryset', None) is not None:
            queryset = self.queryset.all()
        elif getattr(self, 'model', None) is not None:
            queryset = self.model._default_manager.all()
        else:
            raise AttributeError(
                f'{self.__class__.__name__} must define model/queryset or inherit from a class with get_queryset().'
            )
        return queryset.filter(**{f'{self.organization_field}_id': self.get_organization().id})


class OrganizationRolePermissionMixin:
    management_roles = {
        OrganizationMembership.Role.OWNER,
        OrganizationMembership.Role.ADMIN,
    }

    def user_can_manage_organization(self):
        role = user_role_in_org(self.request.user)
        return role in self.management_roles
