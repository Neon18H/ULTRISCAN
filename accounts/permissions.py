from rest_framework.permissions import BasePermission


class IsAnalystOrAdmin(BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        role = getattr(getattr(request.user, 'profile', None), 'role', 'viewer')
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return True
        return role in ('admin', 'analyst')
