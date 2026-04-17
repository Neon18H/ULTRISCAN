from __future__ import annotations

import logging
from typing import Any

from findings.models import Finding
from knowledge_base.models import EndOfLifeRule, MisconfigurationRule, Product, ProductAlias, VulnerabilityRule
from scans.services.versioning import compare_versions, normalize_version, version_in_range

logger = logging.getLogger(__name__)


class CorrelationService:
    SERVICE_ALIASES: dict[str, set[str]] = {
        'http': {'http', 'http-proxy', 'radan-http'},
        'https': {'https', 'https-alt', 'ssl/http'},
        'smb': {'microsoft-ds', 'smb'},
        'mssql': {'ms-sql-s', 'mssql'},
        'elasticsearch': {'elasticsearch', 'wap-wsp'},
    }
    STRICT_EVIDENCE_PRODUCTS = {'wordpress', 'php'}
    STRICT_PRODUCT_RULE_TYPES = {'vulnerability', 'eol'}

    def normalize_service_name(self, raw_service: str) -> str:
        value = (raw_service or '').strip().lower()
        if not value:
            return ''
        for canonical, aliases in self.SERVICE_ALIASES.items():
            if value in aliases:
                return canonical
        return value

    def normalize_product_name(self, raw_product: str) -> str:
        if not raw_product:
            return ''
        value = raw_product.strip()
        alias = ProductAlias.objects.filter(alias__iexact=value).select_related('product').first()
        if alias:
            return alias.product.name
        direct = Product.objects.filter(name__iexact=value).first()
        return direct.name if direct else value

    def _get_product_metadata(self, product_name: str) -> dict[str, str]:
        normalized_name = self.normalize_product_name(product_name)
        if not normalized_name:
            return {'name': '', 'vendor': ''}
        product = Product.objects.filter(name__iexact=normalized_name).first()
        return {
            'name': product.name if product else normalized_name,
            'vendor': (product.vendor if product else '').strip(),
        }

    def correlate_scan_execution(self, scan_execution):
        findings = []
        for service in scan_execution.service_findings.all():
            matched_raw_evidence = self._find_raw_evidence_for_service(scan_execution, service)
            raw_identifier = service.product or service.service
            normalized_product = self.normalize_product_name(raw_identifier)
            normalized_service = self.normalize_service_name(service.service)
            if normalized_product != service.normalized_product:
                service.normalized_product = normalized_product
                service.save(update_fields=['normalized_product', 'updated_at'])
            logger.debug(
                'Correlating service %s scan=%s host=%s service=%s normalized_service=%s product=%s normalized_product=%s '
                'port=%s protocol=%s state=%s',
                service.id,
                scan_execution.id,
                service.host,
                service.service,
                normalized_service,
                service.product,
                normalized_product,
                service.port,
                service.protocol,
                service.state,
            )

            self._ensure_normalized_version(scan_execution, service)

            findings.extend(
                self._apply_vulnerability_rules(scan_execution, service, normalized_product, matched_raw_evidence)
            )
            findings.extend(
                self._apply_misconfiguration_rules(scan_execution, service, normalized_product, matched_raw_evidence)
            )
            findings.extend(
                self._apply_eol_rules(scan_execution, service, normalized_product, matched_raw_evidence)
            )
        return findings

    def _version_in_range(self, current: str, min_version: str, max_version: str) -> bool:
        return version_in_range(current, min_version, max_version)

    def _compare_version(self, current: str, operator: str, expected: str) -> bool:
        if not current or not operator or not expected:
            return False
        return compare_versions(current, operator, expected)


    def _ensure_normalized_version(self, scan_execution, service) -> None:
        raw_version = service.raw_version or service.version
        normalized_version = normalize_version(raw_version)
        update_fields: list[str] = []

        if raw_version and service.raw_version != raw_version:
            service.raw_version = raw_version
            update_fields.append('raw_version')

        if normalized_version != service.normalized_version:
            service.normalized_version = normalized_version
            update_fields.append('normalized_version')

        if update_fields:
            service.save(update_fields=[*update_fields, 'updated_at'])

        if raw_version and not normalized_version:
            logger.warning(
                'Scan %s service_finding=%s has non-comparable version string: %r',
                scan_execution.id,
                service.id,
                raw_version,
            )

    def _collect_evidence_tokens(self, service, raw_evidence=None) -> set[str]:
        values = [service.service, service.product, service.normalized_product, service.banner, service.extrainfo, service.state]
        tokens = {str(v).lower() for v in values if v}
        normalized_service = self.normalize_service_name(service.service)
        if normalized_service:
            tokens.add(normalized_service)
        if service.protocol:
            tokens.add(str(service.protocol).lower())
        if service.port:
            tokens.add(f'port:{service.port}')
        if (service.state or '').lower() == 'open':
            tokens.add('network_exposure')

        for script in service.scripts or []:
            if isinstance(script, dict):
                for key, value in script.items():
                    tokens.add(str(key).lower())
                    tokens.add(str(value).lower())
            else:
                tokens.add(str(script).lower())

        if raw_evidence:
            for source in [raw_evidence.payload, raw_evidence.metadata]:
                for token in self._flatten_tokens(source):
                    tokens.add(token)
        return tokens

    def _flatten_tokens(self, source: Any) -> set[str]:
        flattened: set[str] = set()
        if source is None:
            return flattened
        if isinstance(source, dict):
            for key, value in source.items():
                flattened.add(str(key).strip().lower())
                flattened.update(self._flatten_tokens(value))
            return flattened
        if isinstance(source, (list, tuple, set)):
            for value in source:
                flattened.update(self._flatten_tokens(value))
            return flattened
        value = str(source).strip().lower()
        if value:
            flattened.add(value)
        return flattened

    def _find_raw_evidence_for_service(self, scan_execution, service):
        for evidence in scan_execution.raw_evidences.all():
            if evidence.host and service.host and evidence.host != service.host:
                continue
            ports = (evidence.payload or {}).get('ports') or []
            for parsed_port in ports:
                if (
                    parsed_port.get('port') == service.port
                    and (parsed_port.get('protocol') or '').lower() == (service.protocol or '').lower()
                ):
                    return evidence
        return None

    def _get_version_candidate(self, service) -> str:
        return (
            normalize_version(service.normalized_version)
            or normalize_version(service.raw_version)
            or normalize_version(service.version)
            or ''
        )

    def _is_version_based_rule(self, rule) -> bool:
        return bool(rule.version_operator and rule.version_value) or bool(rule.min_version or rule.max_version)

    def _must_enforce_product_match(self, rule, rule_kind: str) -> bool:
        if rule_kind in self.STRICT_PRODUCT_RULE_TYPES:
            return True
        return self._is_version_based_rule(rule)

    def _product_matches_rule(
        self,
        *,
        rule_product_name: str,
        observed_product_name: str,
        observed_vendor: str,
        rule_vendor: str,
    ) -> tuple[bool, str]:
        if not rule_product_name:
            return False, 'rule has no product configured'
        if not observed_product_name:
            return False, 'service has no detected product'
        if rule_product_name == observed_product_name:
            return True, 'product exact match'
        if rule_vendor and observed_vendor and (rule_vendor == observed_vendor):
            return True, f'vendor-family match ({rule_vendor})'
        return False, f'product mismatch ({rule_product_name} != {observed_product_name})'

    def _rule_matches_service(
        self, rule, service, normalized_product: str, raw_evidence=None, *, rule_kind: str
    ) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        observed_meta = self._get_product_metadata(normalized_product)
        rule_product = (rule.product.name or '').strip().lower()
        observed_product = observed_meta['name'].strip().lower()
        rule_vendor = (rule.product.vendor or '').strip().lower()
        observed_vendor = observed_meta['vendor'].strip().lower()
        product_matches, product_reason = self._product_matches_rule(
            rule_product_name=rule_product,
            observed_product_name=observed_product,
            observed_vendor=observed_vendor,
            rule_vendor=rule_vendor,
        )
        if product_matches:
            reasons.append(product_reason)
        else:
            enforce_product = self._must_enforce_product_match(rule, rule_kind)
            if enforce_product:
                reasons.append(product_reason)
                return False, reasons
            reasons.append(f'{product_reason}; allowed for non-version exposure-style rule')

        if rule_product in self.STRICT_EVIDENCE_PRODUCTS:
            evidence_tokens = self._collect_evidence_tokens(service, raw_evidence)
            explicit_product_token = rule_product in evidence_tokens
            if not explicit_product_token:
                reasons.append(f'missing explicit product evidence for {rule_product}')
                return False, reasons

        expected_service = self.normalize_service_name(rule.service_name)
        observed_service = self.normalize_service_name(service.service)
        if expected_service and expected_service != observed_service:
            reasons.append(f'service mismatch ({expected_service} != {observed_service})')
            return False, reasons
        if rule.port and rule.port != service.port:
            reasons.append(f'port mismatch ({rule.port} != {service.port})')
            return False, reasons
        if rule.protocol and rule.protocol.lower() != (service.protocol or '').lower():
            reasons.append(f'protocol mismatch ({rule.protocol.lower()} != {(service.protocol or "").lower()})')
            return False, reasons
        if rule.required_state and rule.required_state.lower() != (service.state or '').lower():
            reasons.append(f'state mismatch ({rule.required_state.lower()} != {(service.state or "").lower()})')
            return False, reasons

        if rule.version_operator and rule.version_value:
            version_candidate = self._get_version_candidate(service)
            if not self._compare_version(version_candidate, rule.version_operator, rule.version_value):
                reasons.append(
                    f'version compare failed ({version_candidate} {rule.version_operator} {rule.version_value})'
                )
                return False, reasons
        elif rule.min_version or rule.max_version:
            version_candidate = self._get_version_candidate(service)
            if not self._version_in_range(version_candidate, rule.min_version, rule.max_version):
                reasons.append(f'version range failed ({version_candidate} not in {rule.min_version}..{rule.max_version})')
                return False, reasons

        evidence_tokens = self._collect_evidence_tokens(service, raw_evidence)
        if rule.evidence_type and not any(rule.evidence_type.lower() in token for token in evidence_tokens):
            reasons.append(f'evidence_type {rule.evidence_type} not found in tokens')
            return False, reasons
        if rule.required_evidence and not any(rule.required_evidence.lower() in token for token in evidence_tokens):
            reasons.append(f'required_evidence {rule.required_evidence} not found in tokens')
            return False, reasons
        reasons.append('match')
        return True, reasons

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

    def _build_trace(self, *, scan_execution, service, rule, rule_kind: str, raw_evidence, reasons: list[str]) -> dict[str, Any]:
        matched_port_cpe = ''
        if raw_evidence:
            for parsed_port in (raw_evidence.payload or {}).get('ports') or []:
                if (
                    parsed_port.get('port') == service.port
                    and (parsed_port.get('protocol') or '').lower() == (service.protocol or '').lower()
                ):
                    matched_port_cpe = (parsed_port.get('cpe') or '').strip()
                    break
        return {
            'scan_execution_id': scan_execution.id,
            'rule_type': rule_kind,
            'rule_id': rule.id,
            'rule_title': rule.title,
            'rule_product': rule.product.name if rule.product else '',
            'rule_vendor': rule.product.vendor if rule.product else '',
            'match_reasons': reasons,
            'source_evidence': {
                'raw_evidence_id': raw_evidence.id if raw_evidence else None,
                'source': raw_evidence.source if raw_evidence else '',
                'host': service.host,
                'port': service.port,
                'protocol': service.protocol,
                'service': service.service,
            },
            'detected_product': {
                'product': service.product,
                'normalized_product': service.normalized_product or '',
                'vendor': self._get_product_metadata(service.normalized_product or service.product).get('vendor', ''),
                'family_aliases': sorted(
                    ProductAlias.objects.filter(product__name__iexact=service.normalized_product or service.product)
                    .values_list('alias', flat=True)
                ),
                'detected_cpe': matched_port_cpe,
            },
            'detected_version': {
                'raw_version': service.raw_version or service.version,
                'normalized_version': service.normalized_version or '',
                'version_used_for_matching': self._get_version_candidate(service),
            },
        }

    def _upsert_finding(self, *, scan_execution, service, raw_evidence, defaults, lookup, trace):
        finding, created = Finding.objects.get_or_create(
            organization=scan_execution.organization,
            scan_execution=scan_execution,
            service_finding=service,
            **lookup,
            defaults={**defaults, 'raw_evidence': raw_evidence, 'correlation_trace': trace},
        )
        if not created:
            update_fields: list[str] = []
            if finding.raw_evidence_id != (raw_evidence.id if raw_evidence else None):
                finding.raw_evidence = raw_evidence
                update_fields.append('raw_evidence')
            finding.correlation_trace = trace
            update_fields.append('correlation_trace')
            if update_fields:
                finding.save(update_fields=[*update_fields, 'updated_at'])
        return finding

    def _apply_vulnerability_rules(self, scan_execution, service, normalized_product: str, raw_evidence=None):
        created = []
        for rule in VulnerabilityRule.objects.select_related('remediation_template', 'product').prefetch_related('references').all():
            logger.debug(
                'Evaluating rule [vulnerability] scan=%s service=%s detected_product=%s detected_version=%s rule=%s rule_product=%s',
                scan_execution.id,
                service.id,
                normalized_product or service.product,
                self._get_version_candidate(service),
                rule.title,
                rule.product.name if rule.product else '',
            )
            matched, reasons = self._rule_matches_service(
                rule, service, normalized_product, raw_evidence, rule_kind='vulnerability'
            )
            if not matched:
                logger.debug(
                    'Rule miss [vulnerability] rule=%s service=%s scan=%s reasons=%s',
                    rule.title,
                    service.id,
                    scan_execution.id,
                    '; '.join(reasons),
                )
                continue
            trace = self._build_trace(
                scan_execution=scan_execution,
                service=service,
                rule=rule,
                rule_kind='vulnerability',
                raw_evidence=raw_evidence,
                reasons=reasons,
            )
            finding = self._upsert_finding(
                scan_execution=scan_execution,
                service=service,
                raw_evidence=raw_evidence,
                defaults=self._build_defaults(scan_execution, rule),
                lookup={'vulnerability_rule': rule},
                trace=trace,
            )
            logger.debug(
                'Rule match [vulnerability] rule=%s service=%s finding=%s scan=%s trace=%s',
                rule.title,
                service.id,
                finding.id,
                scan_execution.id,
                trace,
            )
            created.append(finding)
        return created

    def _apply_misconfiguration_rules(self, scan_execution, service, normalized_product: str, raw_evidence=None):
        created = []
        for rule in MisconfigurationRule.objects.select_related('remediation_template', 'product').prefetch_related('references').all():
            logger.debug(
                'Evaluating rule [misconfiguration] scan=%s service=%s detected_product=%s detected_version=%s rule=%s rule_product=%s',
                scan_execution.id,
                service.id,
                normalized_product or service.product,
                self._get_version_candidate(service),
                rule.title,
                rule.product.name if rule.product else '',
            )
            matched, reasons = self._rule_matches_service(
                rule, service, normalized_product, raw_evidence, rule_kind='misconfiguration'
            )
            if not matched:
                logger.debug(
                    'Rule miss [misconfiguration] rule=%s service=%s scan=%s reasons=%s',
                    rule.title,
                    service.id,
                    scan_execution.id,
                    '; '.join(reasons),
                )
                continue
            trace = self._build_trace(
                scan_execution=scan_execution,
                service=service,
                rule=rule,
                rule_kind='misconfiguration',
                raw_evidence=raw_evidence,
                reasons=reasons,
            )
            finding = self._upsert_finding(
                scan_execution=scan_execution,
                service=service,
                raw_evidence=raw_evidence,
                defaults=self._build_defaults(scan_execution, rule),
                lookup={'misconfiguration_rule': rule},
                trace=trace,
            )
            logger.debug(
                'Rule match [misconfiguration] rule=%s service=%s finding=%s scan=%s trace=%s',
                rule.title,
                service.id,
                finding.id,
                scan_execution.id,
                trace,
            )
            created.append(finding)
        return created

    def _apply_eol_rules(self, scan_execution, service, normalized_product: str, raw_evidence=None):
        created = []
        for rule in EndOfLifeRule.objects.select_related('remediation_template', 'product').prefetch_related('references').all():
            logger.debug(
                'Evaluating rule [eol] scan=%s service=%s detected_product=%s detected_version=%s rule=%s rule_product=%s',
                scan_execution.id,
                service.id,
                normalized_product or service.product,
                self._get_version_candidate(service),
                rule.title,
                rule.product.name if rule.product else '',
            )
            matched, reasons = self._rule_matches_service(
                rule, service, normalized_product, raw_evidence, rule_kind='eol'
            )
            if not matched:
                logger.debug(
                    'Rule miss [eol] rule=%s service=%s scan=%s reasons=%s',
                    rule.title,
                    service.id,
                    scan_execution.id,
                    '; '.join(reasons),
                )
                continue
            trace = self._build_trace(
                scan_execution=scan_execution,
                service=service,
                rule=rule,
                rule_kind='eol',
                raw_evidence=raw_evidence,
                reasons=reasons,
            )
            finding = self._upsert_finding(
                scan_execution=scan_execution,
                service=service,
                raw_evidence=raw_evidence,
                defaults=self._build_defaults(scan_execution, rule),
                lookup={'end_of_life_rule': rule},
                trace=trace,
            )
            logger.debug(
                'Rule match [eol] rule=%s service=%s finding=%s scan=%s trace=%s',
                rule.title,
                service.id,
                finding.id,
                scan_execution.id,
                trace,
            )
            created.append(finding)
        return created
