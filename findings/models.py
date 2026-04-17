from django.db import models

from accounts.models import Organization
from assets.models import Asset
from core.models import TimeStampedModel
from knowledge_base.models import EndOfLifeRule, MisconfigurationRule, VulnerabilityRule
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
    asset = models.ForeignKey(Asset, null=True, blank=True, on_delete=models.CASCADE, related_name='findings')
    scan_execution = models.ForeignKey(ScanExecution, on_delete=models.CASCADE, related_name='findings')
    service_finding = models.ForeignKey(ServiceFinding, null=True, blank=True, on_delete=models.SET_NULL)
    raw_evidence = models.ForeignKey(RawEvidence, null=True, blank=True, on_delete=models.SET_NULL)
    vulnerability_rule = models.ForeignKey(VulnerabilityRule, null=True, blank=True, on_delete=models.SET_NULL)
    misconfiguration_rule = models.ForeignKey(MisconfigurationRule, null=True, blank=True, on_delete=models.SET_NULL)
    end_of_life_rule = models.ForeignKey(EndOfLifeRule, null=True, blank=True, on_delete=models.SET_NULL)
    title = models.CharField(max_length=200)
    description = models.TextField()
    remediation = models.TextField(blank=True)
    reference = models.URLField(blank=True)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    confidence = models.CharField(max_length=20, choices=Confidence.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    analyst_notes = models.TextField(blank=True)
    correlation_trace = models.JSONField(default=dict, blank=True)
    ai_title = models.CharField(max_length=255, blank=True)
    ai_summary = models.TextField(blank=True)
    ai_impact = models.TextField(blank=True)
    ai_remediation = models.TextField(blank=True)
    ai_priority_reason = models.TextField(blank=True)
    ai_confidence = models.CharField(max_length=20, blank=True)
    ai_tags = models.JSONField(default=list, blank=True)
    ai_owasp_category = models.CharField(max_length=120, blank=True)
    ai_cwe = models.CharField(max_length=80, blank=True)
    ai_generated_at = models.DateTimeField(null=True, blank=True)
    ai_enrichment = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title
