from django.conf import settings
from django.db import models

from accounts.models import Organization
from core.models import TimeStampedModel
from .providers import provider_choices


class ProviderArtifact(TimeStampedModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='provider_artifacts')
    firewall = models.CharField(max_length=120, blank=True)
    provider = models.CharField(max_length=30, choices=provider_choices(), default='other')
    resource_name = models.CharField(max_length=160)
    resource_type = models.CharField(max_length=80, blank=True)
    region = models.CharField(max_length=80, blank=True)
    private_ip = models.GenericIPAddressField(null=True, blank=True)
    public_ip = models.GenericIPAddressField(null=True, blank=True)
    log_type = models.CharField(max_length=80, blank=True)
    raw_log = models.JSONField(default=dict, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='uploaded_provider_artifacts',
    )

    class Meta:
        verbose_name = 'Provider artifact'
        verbose_name_plural = 'Provider artifacts'
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['organization', 'provider']),
            models.Index(fields=['organization', 'private_ip']),
            models.Index(fields=['organization', 'firewall']),
        ]

    def __str__(self) -> str:
        return f'{self.resource_name} ({self.provider})'

    @property
    def provider_label(self):
        return dict(provider_choices()).get(self.provider, self.provider)
