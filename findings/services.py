from packaging import version

from knowledge_base.models import MisconfigurationRule, VulnerabilityRule
from .models import Finding


def _version_in_range(current: str, min_version: str, max_version: str) -> bool:
    if not current:
        return False
    v = version.parse(current)
    if min_version and v < version.parse(min_version):
        return False
    if max_version and v > version.parse(max_version):
        return False
    return True


def correlate_scan_execution(scan_execution):
    for service in scan_execution.service_findings.all():
        for rule in VulnerabilityRule.objects.filter(product__name__iexact=service.product):
            if rule.port and rule.port != service.port:
                continue
            if rule.protocol and rule.protocol.lower() != service.protocol.lower():
                continue
            if (rule.min_version or rule.max_version) and not _version_in_range(service.version, rule.min_version, rule.max_version):
                continue
            Finding.objects.get_or_create(
                organization=scan_execution.organization, scan_execution=scan_execution, service_finding=service, vulnerability_rule=rule,
                defaults={'title': rule.title, 'description': rule.description, 'remediation': rule.remediation_template.body if rule.remediation_template else '', 'severity': rule.severity, 'confidence': rule.confidence},
            )
        for rule in MisconfigurationRule.objects.filter(port=service.port):
            Finding.objects.get_or_create(
                organization=scan_execution.organization, scan_execution=scan_execution, service_finding=service, misconfiguration_rule=rule,
                defaults={'title': rule.title, 'description': rule.description, 'remediation': rule.remediation_template.body if rule.remediation_template else '', 'severity': rule.severity, 'confidence': rule.confidence},
            )
