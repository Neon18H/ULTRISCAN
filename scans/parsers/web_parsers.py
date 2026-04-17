from __future__ import annotations

import json
from urllib.parse import urlparse

from scans.engines.tooling import parse_json_lines


def parse_whatweb_json(raw_output: str) -> dict:
    def _normalize(payload: object) -> dict:
        if isinstance(payload, list) and payload:
            first = payload[0]
            return first if isinstance(first, dict) else {}
        if isinstance(payload, dict):
            if isinstance(payload.get('plugins'), dict):
                return payload
            if len(payload) == 1:
                first = next(iter(payload.values()))
                if isinstance(first, dict) and isinstance(first.get('plugins'), dict):
                    return first
            return payload
        return {}

    raw = (raw_output or '').strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return _normalize(parsed)
    except json.JSONDecodeError:
        pass

    for line in raw.splitlines():
        candidate = line.strip()
        if not candidate or not candidate.startswith(('{', '[')):
            continue
        try:
            parsed_line = json.loads(candidate)
            normalized = _normalize(parsed_line)
            if normalized:
                return normalized
        except json.JSONDecodeError:
            continue
    return {}


def parse_gobuster_json(raw_output: str) -> list[dict]:
    rows = parse_json_lines(raw_output)
    endpoints: list[dict] = []
    for row in rows:
        path = row.get('path') or row.get('url') or row.get('input') or ''
        status = row.get('status') or row.get('status_code')
        if path:
            endpoints.append({'path': path, 'status_code': status})
    return endpoints


def parse_nuclei_json(raw_output: str) -> list[dict]:
    rows = parse_json_lines(raw_output)
    vulns: list[dict] = []
    for row in rows:
        info = row.get('info') or {}
        references = info.get('reference') or info.get('references') or []
        if isinstance(references, str):
            references = [references]
        vulns.append(
            {
                'template_id': row.get('template-id', ''),
                'name': info.get('name', row.get('matcher-name', 'Nuclei finding')),
                'severity': (info.get('severity') or 'medium').lower(),
                'description': info.get('description', ''),
                'reference': references[0] if references else '',
                'matched_at': row.get('matched-at', ''),
                'template_path': row.get('template', ''),
                'type': 'nuclei',
            }
        )
    return vulns


def parse_nikto_text(raw_output: str) -> list[dict]:
    findings: list[dict] = []
    for line in (raw_output or '').splitlines():
        entry = line.strip()
        if not entry or not entry.startswith('+'):
            continue
        findings.append(
            {
                'name': entry[:120],
                'severity': 'low',
                'description': entry,
                'reference': '',
                'type': 'nikto',
            }
        )
    return findings


def parse_wpscan_json(raw_output: str) -> dict:
    try:
        payload = json.loads(raw_output)
        return payload if isinstance(payload, dict) else {}
    except json.JSONDecodeError:
        return {}


def url_host_port(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.hostname or url
    port = parsed.port
    if not port:
        port = 443 if parsed.scheme == 'https' else 80
    return host, port
