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


class ExternalAdvisory(TimeStampedModel):
    class Source(models.TextChoices):
        NVD = 'NVD', 'NVD'

    source = models.CharField(max_length=20, choices=Source.choices, default=Source.NVD)
    cve_id = models.CharField(max_length=32, unique=True, db_index=True)
    title = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    last_modified_at = models.DateTimeField(null=True, blank=True)
    severity = models.CharField(max_length=20, blank=True)
    cvss_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    cvss_vector = models.CharField(max_length=255, blank=True)
    cvss_version = models.CharField(max_length=20, blank=True)
    has_kev = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict, blank=True)
    raw_payload = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-last_modified_at', 'cve_id']
        indexes = [models.Index(fields=['source', 'last_modified_at'])]

    def __str__(self):
        return f'{self.source}:{self.cve_id}'


class ExternalAdvisoryReference(TimeStampedModel):
    advisory = models.ForeignKey(ExternalAdvisory, on_delete=models.CASCADE, related_name='references')
    url = models.TextField()
    source = models.CharField(max_length=255, blank=True)
    tags = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ['advisory_id', 'id']
        unique_together = [('advisory', 'url')]


class ExternalAdvisoryWeakness(TimeStampedModel):
    advisory = models.ForeignKey(ExternalAdvisory, on_delete=models.CASCADE, related_name='weaknesses')
    source = models.CharField(max_length=255, blank=True)
    cwe_id = models.CharField(max_length=80, blank=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['advisory_id', 'cwe_id', 'id']
        indexes = [models.Index(fields=['cwe_id'])]
        constraints = [
            models.UniqueConstraint(fields=['advisory', 'cwe_id'], name='kb_unique_advisory_cwe'),
        ]


class ExternalAdvisoryMetric(TimeStampedModel):
    advisory = models.ForeignKey(ExternalAdvisory, on_delete=models.CASCADE, related_name='metrics')
    source = models.CharField(max_length=255, blank=True)
    metric_type = models.CharField(max_length=40)
    cvss_version = models.CharField(max_length=20, blank=True)
    base_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    base_severity = models.CharField(max_length=20, blank=True)
    vector_string = models.CharField(max_length=255, blank=True)
    exploitability_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    impact_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    raw_payload = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['advisory_id', 'metric_type', 'source', 'id']
        constraints = [
            models.UniqueConstraint(
                fields=['advisory', 'source', 'metric_type', 'cvss_version'],
                name='kb_unique_advisory_metric_signature',
            ),
        ]


class ExternalAdvisoryCpeMatch(TimeStampedModel):
    advisory = models.ForeignKey(ExternalAdvisory, on_delete=models.CASCADE, related_name='cpe_matches')
    vulnerable = models.BooleanField(default=True)
    criteria = models.CharField(max_length=1024)
    match_criteria_id = models.CharField(max_length=80, blank=True)
    version_start_including = models.CharField(max_length=120, blank=True)
    version_start_excluding = models.CharField(max_length=120, blank=True)
    version_end_including = models.CharField(max_length=120, blank=True)
    version_end_excluding = models.CharField(max_length=120, blank=True)

    class Meta:
        ordering = ['advisory_id', 'id']
        constraints = [
            models.UniqueConstraint(
                fields=[
                    'advisory',
                    'criteria',
                    'version_start_including',
                    'version_start_excluding',
                    'version_end_including',
                    'version_end_excluding',
                ],
                name='kb_unique_advisory_cpe_signature',
            ),
        ]


class AdvisorySyncJob(TimeStampedModel):
    class Status(models.TextChoices):
        STARTED = 'started', 'Started'
        SUCCEEDED = 'succeeded', 'Succeeded'
        FAILED = 'failed', 'Failed'

    source = models.CharField(max_length=20, default=ExternalAdvisory.Source.NVD)
    command = models.CharField(max_length=120)
    filters = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.STARTED)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    total_fetched = models.PositiveIntegerField(default=0)
    total_created = models.PositiveIntegerField(default=0)
    total_updated = models.PositiveIntegerField(default=0)
    total_errors = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f'{self.source}:{self.command}:{self.status}'
