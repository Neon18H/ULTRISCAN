from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from accounts.models import Organization
from assets.models import Asset
from core.models import TimeStampedModel
from scan_profiles.models import ScanProfile


class ScanExecution(TimeStampedModel):
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        QUEUED = 'queued', 'Queued'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
        CANCELLED = 'cancelled', 'Cancelled'

    WEB_STAGE_CHOICES = (
        ('queued', 'Queued'),
        ('http_probe', 'HTTP probe'),
        ('fingerprint', 'Fingerprint'),
        ('endpoint_discovery', 'Endpoint discovery'),
        ('vulnerability_checks', 'Vulnerability checks'),
        ('correlation', 'Correlation'),
        ('reporting', 'Reporting'),
        ('completed', 'Completed'),
    )
    INFRA_STAGE_CHOICES = (
        ('queued', 'Queued'),
        ('discovery', 'Discovery'),
        ('service_detection', 'Service detection'),
        ('version_detection', 'Version detection'),
        ('enrichment', 'Enrichment'),
        ('correlation', 'Correlation'),
        ('reporting', 'Reporting'),
        ('completed', 'Completed'),
    )
    STAGE_LABELS = dict(WEB_STAGE_CHOICES + INFRA_STAGE_CHOICES)

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='scan_executions')
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='scan_executions')
    profile = models.ForeignKey(ScanProfile, on_delete=models.PROTECT, related_name='scan_executions')
    launched_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name='launched_scans')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)
    summary = models.JSONField(default=dict, blank=True)
    command_executed = models.TextField(blank=True)
    engine_metadata = models.JSONField(default=dict, blank=True)
    is_archived = models.BooleanField(default=False)
    archived_at = models.DateTimeField(null=True, blank=True)
    progress_percent = models.PositiveSmallIntegerField(default=0, validators=[MinValueValidator(0), MaxValueValidator(100)])
    progress_stage = models.CharField(max_length=40, default='queued', blank=True)
    status_message = models.CharField(max_length=255, blank=True)

    @property
    def progress_stage_label(self) -> str:
        return self.STAGE_LABELS.get(self.progress_stage, self.progress_stage.replace('_', ' ').title())


class RawEvidence(TimeStampedModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='raw_evidences')
    scan_execution = models.ForeignKey(ScanExecution, on_delete=models.CASCADE, related_name='raw_evidences')
    source = models.CharField(max_length=50, default='nmap')
    host = models.CharField(max_length=255)
    payload = models.JSONField(default=dict)
    raw_output = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)


class ServiceFinding(TimeStampedModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='service_findings')
    scan_execution = models.ForeignKey(ScanExecution, on_delete=models.CASCADE, related_name='service_findings')
    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10)
    state = models.CharField(max_length=20)
    service = models.CharField(max_length=120, blank=True)
    product = models.CharField(max_length=120, blank=True)
    normalized_product = models.CharField(max_length=120, blank=True)
    version = models.CharField(max_length=120, blank=True)
    raw_version = models.CharField(max_length=200, blank=True)
    normalized_version = models.CharField(max_length=120, blank=True)
    extrainfo = models.CharField(max_length=200, blank=True)
    banner = models.TextField(blank=True)
    scripts = models.JSONField(default=list, blank=True)


class WebFinding(TimeStampedModel):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='web_findings')
    scan_execution = models.ForeignKey(ScanExecution, on_delete=models.CASCADE, related_name='web_findings')
    host = models.CharField(max_length=255)
    url = models.URLField()
    title = models.CharField(max_length=255, blank=True)
    technology = models.CharField(max_length=120, blank=True)
    evidence = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
