from django.db import models

from accounts.models import Organization
from core.models import TimeStampedModel
from knowledge_base.models import MisconfigurationRule, VulnerabilityRule
from scans.models import RawEvidence, ScanExecution, ServiceFinding


class Finding(TimeStampedModel):
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

    class Status(models.TextChoices):
        OPEN = 'open', 'Open'
        ACCEPTED_RISK = 'accepted_risk', 'Accepted Risk'
        MITIGATED = 'mitigated', 'Mitigated'
        REMEDIATED = 'remediated', 'Remediated'
        FALSE_POSITIVE = 'false_positive', 'False Positive'

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='findings')
    scan_execution = models.ForeignKey(ScanExecution, on_delete=models.CASCADE, related_name='findings')
    service_finding = models.ForeignKey(ServiceFinding, null=True, blank=True, on_delete=models.SET_NULL)
    raw_evidence = models.ForeignKey(RawEvidence, null=True, blank=True, on_delete=models.SET_NULL)
    vulnerability_rule = models.ForeignKey(VulnerabilityRule, null=True, blank=True, on_delete=models.SET_NULL)
    misconfiguration_rule = models.ForeignKey(MisconfigurationRule, null=True, blank=True, on_delete=models.SET_NULL)
    title = models.CharField(max_length=200)
    description = models.TextField()
    remediation = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    confidence = models.CharField(max_length=20, choices=Confidence.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    analyst_notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title
