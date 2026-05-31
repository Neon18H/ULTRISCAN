from django.contrib import admin

from .models import ProviderArtifact


@admin.register(ProviderArtifact)
class ProviderArtifactAdmin(admin.ModelAdmin):
    list_display = ('resource_name', 'provider', 'resource_type', 'region', 'private_ip', 'firewall', 'organization', 'uploaded_at')
    list_filter = ('provider', 'resource_type', 'organization')
    search_fields = ('resource_name', 'resource_type', 'region', 'private_ip', 'public_ip', 'firewall')
