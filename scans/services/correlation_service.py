from __future__ import annotations

from packaging import version

from findings.models import Finding
from knowledge_base.models import EndOfLifeRule, MisconfigurationRule, Product, ProductAlias, VulnerabilityRule


class CorrelationService:
    def normalize_product_name(self, raw_product: str) -> str:
        if not raw_product:
            return ''
        alias = ProductAlias.objects.filter(alias__iexact=raw_product.strip()).select_related('product').first()
        if alias:
            return alias.product.name
        direct = Product.objects.filter(name__iexact=raw_product.strip()).first()
        return direct.name if direct else raw_product.strip()

    def correlate_scan_execution(self, scan_execution):
        findings = []
        for service in scan_execution.service_findings.all():
            normalized_product = self.normalize_product_name(service.product or service.service)
            if normalized_product != service.normalized_product:
                service.normalized_product = normalized_product
                service.save(update_fields=['normalized_product', 'updated_at'])

            findings.extend(self._apply_vulnerability_rules(scan_execution, service, normalized_product))
            findings.extend(self._apply_misconfiguration_rules(scan_execution, service, normalized_product))
            findings.extend(self._apply_eol_rules(scan_execution, service, normalized_product))
        return findings

    def _version_in_range(self, current: str, min_version: str, max_version: str) -> bool:
        if not current:
            return False
        v = version.parse(current)
        if min_version and v < version.parse(min_version):
            return False
        if max_version and v > version.parse(max_version):
            return False
        return True

    def _rule_matches_service(self, rule, service, normalized_product: str) -> bool:
        if rule.product.name.lower() != normalized_product.lower():
            return False
        if rule.port and rule.port != service.port:
            return False
        if rule.protocol and rule.protocol.lower() != service.protocol.lower():
            return False
        if (rule.min_version or rule.max_version) and not self._version_in_range(service.version, rule.min_version, rule.max_version):
            return False
        if rule.required_evidence and rule.required_evidence.lower() not in (service.banner or '').lower():
            return False
        return True

    def _build_defaults(self, scan_execution, rule):
        refs = getattr(rule, 'references', None)
        first_ref = refs.first().url if refs and refs.exists() else ''
        remediation = rule.remediation_template.body if rule.remediation_template else ''
        return {
            'asset': scan_execution.asset,
            'title': rule.title,
            'description': rule.description,
            'remediation': remediation,
            'reference': first_ref,
            'severity': rule.severity,
            'confidence': rule.confidence,
            'status': Finding.Status.OPEN,
        }

    def _apply_vulnerability_rules(self, scan_execution, service, normalized_product: str):
        created = []
        for rule in VulnerabilityRule.objects.select_related('remediation_template', 'product').prefetch_related('references').all():
            if not self._rule_matches_service(rule, service, normalized_product):
                continue
            finding, _ = Finding.objects.get_or_create(
                organization=scan_execution.organization,
                scan_execution=scan_execution,
                service_finding=service,
                vulnerability_rule=rule,
                defaults=self._build_defaults(scan_execution, rule),
            )
            created.append(finding)
        return created

    def _apply_misconfiguration_rules(self, scan_execution, service, normalized_product: str):
        created = []
        for rule in MisconfigurationRule.objects.select_related('remediation_template', 'product').prefetch_related('references').all():
            if not self._rule_matches_service(rule, service, normalized_product):
                continue
            finding, _ = Finding.objects.get_or_create(
                organization=scan_execution.organization,
                scan_execution=scan_execution,
                service_finding=service,
                misconfiguration_rule=rule,
                defaults=self._build_defaults(scan_execution, rule),
            )
            created.append(finding)
        return created

    def _apply_eol_rules(self, scan_execution, service, normalized_product: str):
        created = []
        for rule in EndOfLifeRule.objects.select_related('remediation_template', 'product').prefetch_related('references').all():
            if not self._rule_matches_service(rule, service, normalized_product):
                continue
            finding, _ = Finding.objects.get_or_create(
                organization=scan_execution.organization,
                scan_execution=scan_execution,
                service_finding=service,
                end_of_life_rule=rule,
                defaults=self._build_defaults(scan_execution, rule),
            )
            created.append(finding)
        return created
