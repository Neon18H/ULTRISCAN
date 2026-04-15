from scans.services.correlation_service import CorrelationService


def _version_in_range(current: str, min_version: str, max_version: str) -> bool:
    return CorrelationService()._version_in_range(current, min_version, max_version)


def correlate_scan_execution(scan_execution):
    return CorrelationService().correlate_scan_execution(scan_execution)
