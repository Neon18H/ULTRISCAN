from __future__ import annotations

import logging
import time
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)


class NVDClientError(Exception):
    pass


class NVDClient:
    BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    CVE_HISTORY_URL = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0'

    def __init__(
        self,
        api_key: str | None = None,
        timeout: int = 30,
        max_retries: int = 3,
        min_interval_seconds: float = 0.7,
    ) -> None:
        self.api_key = api_key if api_key is not None else settings.NVD_API_KEY
        self.timeout = timeout
        self.max_retries = max_retries
        self.min_interval_seconds = min_interval_seconds
        self._last_request_at = 0.0

    def _headers(self) -> dict[str, str]:
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['apiKey'] = self.api_key
        return headers

    def _sleep_if_needed(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.min_interval_seconds:
            time.sleep(self.min_interval_seconds - elapsed)

    def request_cves(self, params: dict[str, Any]) -> dict[str, Any]:
        attempts = 0
        while attempts < self.max_retries:
            attempts += 1
            self._sleep_if_needed()
            try:
                try:
                    import requests
                except ImportError as exc:
                    raise NVDClientError('requests dependency is required. Run pip install -r requirements.txt') from exc

                response = requests.get(
                    self.BASE_URL,
                    params=params,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
                self._last_request_at = time.monotonic()
                if response.status_code >= 500:
                    raise NVDClientError(f'NVD upstream error ({response.status_code})')
                if response.status_code >= 400:
                    raise NVDClientError(f'NVD request failed ({response.status_code}): {response.text[:500]}')
                return response.json()
            except (requests.RequestException, ValueError, NVDClientError) as exc:
                logger.warning('NVD request failed on attempt %s/%s: %s', attempts, self.max_retries, exc)
                if attempts >= self.max_retries:
                    raise NVDClientError(str(exc)) from exc
                time.sleep(min(2 ** attempts, 10))

        raise NVDClientError('NVD request could not complete')

    def iter_cve_pages(self, results_per_page: int | None = None, start_index: int = 0, **filters: Any):
        current_start_index = int(start_index or filters.pop('startIndex', 0) or 0)
        results_per_page = int(results_per_page or settings.NVD_SYNC_PAGE_SIZE)

        while True:
            params = {
                'startIndex': current_start_index,
                'resultsPerPage': results_per_page,
            }
            allowed_filters = {'cveId', 'cpeName', 'hasKev', 'lastModStartDate', 'lastModEndDate'}
            for key, value in filters.items():
                if value is None or value == '' or key not in allowed_filters:
                    continue
                params[key] = value

            payload = self.request_cves(params)
            vulnerabilities = payload.get('vulnerabilities', [])
            total_results = int(payload.get('totalResults', 0))
            if not vulnerabilities:
                break

            yield {
                'start_index': current_start_index,
                'vulnerabilities': vulnerabilities,
                'total_results': total_results,
                'results_per_page': results_per_page,
            }

            current_start_index += len(vulnerabilities)
            if current_start_index >= total_results:
                break

    def iter_cves(self, results_per_page: int | None = None, **filters: Any):
        for page in self.iter_cve_pages(results_per_page=results_per_page, **filters):
            for item in page['vulnerabilities']:
                yield item
