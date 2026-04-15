from __future__ import annotations

from packaging import version

from findings.models import Finding
from knowledge_base.models import EndOfLifeRule, MisconfigurationRule, Product, ProductAlias, VulnerabilityRule


class CorrelationService:
    def normalize_product_name(self, raw_product: str) -> str:
        if not raw_product:
            return ''
        value = raw_product.strip()
        alias = ProductAlias.objects.filter(alias__iexact=value).select_related('product').first()
        if alias:
            return alias.product.name
        direct = Product.objects.filter(name__iexact=value).first()
        return direct.name if direct else value

    def correlate_scan_execution(self, scan_execution):
        findings = []
        for service in scan_execution.service_findings.all():
            raw_identifier = service.product or service.service
            normalized_product = self.normalize_product_name(raw_identifier)
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

    def _compare_version(self, current: str, operator: str, expected: str) -> bool:
        if not current or not operator or not expected:
            return False
        parsed_current = version.parse(current)
        parsed_expected = version.parse(expected)
        if operator == '<':
            return parsed_current < parsed_expected
        if operator == '<=':
            return parsed_current <= parsed_expected
        if operator == '>':
            return parsed_current > parsed_expected
        if operator == '>=':
            return parsed_current >= parsed_expected
        if operator == '==':
            return parsed_current == parsed_expected
        return False

    def _collect_evidence_tokens(self, service) -> set[str]:
        values = [service.service, service.product, service.normalized_product, service.banner, service.extrainfo, service.state]
        tokens = {str(v).lower() for v in values if v}
        if (service.state or '').lower() == 'open':
            tokens.add('network_exposure')

        for script in service.scripts or []:
            if isinstance(script, dict):
                for key, value in script.items():
                    tokens.add(str(key).lower())
                    tokens.add(str(value).lower())
            else:
                tokens.add(str(script).lower())
        return tokens

    def _rule_matches_service(self, rule, service, normalized_product: str) -> bool:
        if rule.product.name.lower() != normalized_product.lower():
            return False
        if rule.service_name and rule.service_name.lower() != (service.service or '').lower():
            return False
        if rule.port and rule.port != service.port:
            return False
        if rule.protocol and rule.protocol.lower() != (service.protocol or '').lower():
            return False
        if rule.required_state and rule.required_state.lower() != (service.state or '').lower():
            return False

        if rule.version_operator and rule.version_value:
            if not self._compare_version(service.version, rule.version_operator, rule.version_value):
                return False
        elif rule.min_version or rule.max_version:
            if not self._version_in_range(service.version, rule.min_version, rule.max_version):
                return False

        evidence_tokens = self._collect_evidence_tokens(service)
        if rule.evidence_type and not any(rule.evidence_type.lower() in token for token in evidence_tokens):
            return False
        if rule.required_evidence and not any(rule.required_evidence.lower() in token for token in evidence_tokens):
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
