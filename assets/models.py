import ipaddress
import re

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import models

from core.models import TimeStampedModel


class Asset(TimeStampedModel):
    class AssetType(models.TextChoices):
        IP = 'ip', 'IP'
        CIDR = 'cidr', 'Rango CIDR'
        DOMAIN = 'domain', 'Dominio'
        URL = 'url', 'URL'

    class Criticality(models.TextChoices):
        LOW = 'low', 'Baja'
        MEDIUM = 'medium', 'Media'
        HIGH = 'high', 'Alta'
        CRITICAL = 'critical', 'Crítica'

    class Status(models.TextChoices):
        ACTIVE = 'active', 'Activo'
        INACTIVE = 'inactive', 'Inactivo'

    name = models.CharField(max_length=120)
    asset_type = models.CharField(max_length=20, choices=AssetType.choices)
    value = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    criticality = models.CharField(max_length=20, choices=Criticality.choices, default=Criticality.MEDIUM)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    tags = models.CharField(max_length=255, blank=True)

    class Meta:
        verbose_name = 'Activo'
        verbose_name_plural = 'Activos'
        ordering = ['-created_at']
        indexes = [models.Index(fields=['asset_type', 'value']), models.Index(fields=['status'])]

    def __str__(self) -> str:
        return f'{self.name} ({self.value})'

    def clean(self) -> None:
        validators = {self.AssetType.IP: self._validate_ip, self.AssetType.CIDR: self._validate_cidr, self.AssetType.DOMAIN: self._validate_domain, self.AssetType.URL: self._validate_url}
        validator = validators.get(self.asset_type)
        if validator:
            validator()

    def _validate_ip(self) -> None:
        try:
            ipaddress.ip_address(self.value)
        except ValueError as exc:
            raise ValidationError({'value': 'IP inválida.'}) from exc

    def _validate_cidr(self) -> None:
        try:
            ipaddress.ip_network(self.value, strict=False)
        except ValueError as exc:
            raise ValidationError({'value': 'CIDR inválido.'}) from exc

    def _validate_domain(self) -> None:
        if not re.match(r'^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$', self.value):
            raise ValidationError({'value': 'Dominio inválido.'})

    def _validate_url(self) -> None:
        URLValidator()(self.value)
