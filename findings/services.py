from scans.services.correlation_service import CorrelationService
from findings.ai_enrichment import AIFindingEnrichmentService


def _version_in_range(current: str, min_version: str, max_version: str) -> bool:
    return CorrelationService()._version_in_range(current, min_version, max_version)


def correlate_scan_execution(scan_execution):
    return CorrelationService().correlate_scan_execution(scan_execution)


def enrich_findings_with_ai(findings):
    return AIFindingEnrichmentService().enrich_findings(findings)
