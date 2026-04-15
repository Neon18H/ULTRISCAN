from rest_framework.exceptions import PermissionDenied

from accounts.tenancy import get_active_organization


class TenantModelViewSetMixin:
    organization_field = 'organization'

    def get_organization(self):
        org = get_active_organization(self.request.user)
        if not org:
            raise PermissionDenied('No existe organización activa.')
        return org

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(**{self.organization_field: self.get_organization()})

    def perform_create(self, serializer):
        serializer.save(**{self.organization_field: self.get_organization()})
