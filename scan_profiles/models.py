from django.db import models

from accounts.models import Organization
from core.models import TimeStampedModel


class ScanProfile(TimeStampedModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='scan_profiles')
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    host_discovery = models.BooleanField(default=True)
    port_detection = models.BooleanField(default=True)
    version_detection = models.BooleanField(default=True)
    web_detection = models.BooleanField(default=False)
    light_enumeration = models.BooleanField(default=False)
    wordpress_scan = models.BooleanField(default=False)
    web_scan_preset = models.CharField(max_length=12, default='medium')
    web_scan_defaults = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = 'Perfil de escaneo'
        verbose_name_plural = 'Perfiles de escaneo'
        ordering = ['name']
        unique_together = ('organization', 'name')

    def __str__(self) -> str:
        return self.name
