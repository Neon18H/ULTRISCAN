from rest_framework.permissions import BasePermission

from accounts.models import OrganizationMembership
from accounts.tenancy import get_active_membership


class TenantAccessPermission(BasePermission):
    edit_roles = {
        OrganizationMembership.Role.OWNER,
        OrganizationMembership.Role.ADMIN,
        OrganizationMembership.Role.ANALYST,
    }

    def has_permission(self, request, view):
        membership = get_active_membership(request.user)
        if not membership:
            return False
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return True
        return membership.role in self.edit_roles


class OrganizationAdminPermission(BasePermission):
    allowed_roles = {
        OrganizationMembership.Role.OWNER,
        OrganizationMembership.Role.ADMIN,
    }

    def has_permission(self, request, view):
        membership = get_active_membership(request.user)
        return bool(membership and membership.role in self.allowed_roles)
