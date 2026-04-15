from django.db import models
from core.models import TimeStampedModel


class Product(TimeStampedModel):
    name = models.CharField(max_length=120, unique=True)
    vendor = models.CharField(max_length=120, blank=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class ProductAlias(TimeStampedModel):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='aliases')
    alias = models.CharField(max_length=120, unique=True)

    class Meta:
        ordering = ['alias']

    def __str__(self):
        return self.alias


class RemediationTemplate(TimeStampedModel):
    title = models.CharField(max_length=150)
    body = models.TextField()

    def __str__(self):
        return self.title


class BaseRule(TimeStampedModel):
    class Severity(models.TextChoices):
        INFO = 'info', 'Info'
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'

    class Confidence(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'

    title = models.CharField(max_length=180)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='%(class)s_rules')
    min_version = models.CharField(max_length=50, blank=True)
    max_version = models.CharField(max_length=50, blank=True)
    version_operator = models.CharField(max_length=4, blank=True)
    version_value = models.CharField(max_length=50, blank=True)
    service_name = models.CharField(max_length=120, blank=True)
    port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, blank=True)
    required_state = models.CharField(max_length=20, blank=True)
    evidence_type = models.CharField(max_length=80, blank=True)
    required_evidence = models.CharField(max_length=150, blank=True)
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.LOW)
    cvss = models.DecimalField(max_digits=3, decimal_places=1, default=0.0)
    confidence = models.CharField(max_length=20, choices=Confidence.choices, default=Confidence.MEDIUM)
    description = models.TextField()
    remediation_template = models.ForeignKey(RemediationTemplate, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        abstract = True


class VulnerabilityRule(BaseRule):
    cve = models.CharField(max_length=40, blank=True)


class MisconfigurationRule(BaseRule):
    pass


class EndOfLifeRule(BaseRule):
    eol_date = models.DateField(null=True, blank=True)


class ReferenceLink(TimeStampedModel):
    vulnerability_rule = models.ForeignKey(VulnerabilityRule, null=True, blank=True, on_delete=models.CASCADE, related_name='references')
    misconfiguration_rule = models.ForeignKey(MisconfigurationRule, null=True, blank=True, on_delete=models.CASCADE, related_name='references')
    end_of_life_rule = models.ForeignKey(EndOfLifeRule, null=True, blank=True, on_delete=models.CASCADE, related_name='references')
    label = models.CharField(max_length=120)
    url = models.URLField()
