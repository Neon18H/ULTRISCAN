from django.db import models
from core.models import TimeStampedModel


class ScanProfile(TimeStampedModel):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    host_discovery = models.BooleanField(default=True)
    port_detection = models.BooleanField(default=True)
    version_detection = models.BooleanField(default=True)
    web_detection = models.BooleanField(default=False)
    light_enumeration = models.BooleanField(default=False)
    wordpress_scan = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Perfil de escaneo'
        verbose_name_plural = 'Perfiles de escaneo'
        ordering = ['name']

    def __str__(self) -> str:
        return self.name
