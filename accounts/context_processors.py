from .tenancy import get_active_membership


def tenant_context(request):
    membership = get_active_membership(request.user)
    return {
        'current_membership': membership,
        'current_organization': membership.organization if membership else None,
        'current_role': membership.role if membership else None,
    }
