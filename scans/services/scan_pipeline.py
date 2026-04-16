from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree as ET

from django.db import transaction

from findings.models import Finding
from integrations.parsers.nmap_parser import NmapXmlParser
from integrations.runners.nmap_runner import NmapRunner
from scans.engines.tooling import ExternalToolRunner
from scans.models import RawEvidence, ScanExecution, ServiceFinding, WebFinding
from scans.parsers.web_parsers import (
    parse_gobuster_json,
    parse_nikto_text,
    parse_nuclei_json,
    parse_whatweb_json,
    parse_wpscan_json,
    url_host_port,
)
from scans.services.versioning import normalize_version


INFRA_SCAN_TYPES = {
    'nmap_discovery',
    'nmap_full',
    'nmap_services',
    'nmap_full_tcp_safe',
    'infra_discovery',
    'infra_standard',
    'infra_deep',
}
WEB_SCAN_TYPES = {'web_basic', 'web_full', 'web_wordpress', 'web_api', 'wordpress_scan'}

NMAP_PROFILE_BY_SCAN_TYPE = {
    'nmap_discovery': 'discovery',
    'nmap_full': 'infra_standard',
    'nmap_services': 'infra_standard',
    'nmap_full_tcp_safe': 'infra_standard',
    'infra_discovery': 'discovery',
    'infra_standard': 'infra_standard',
    'infra_deep': 'infra_deep',
}


@dataclass
class ScanPipelineResult:
    summary: dict[str, Any]
    command_executed: str
    engine_metadata: dict[str, Any]


class ScanPipelineExecutionError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        command: str = '',
        stdout: str = '',
        stderr: str = '',
        retryable: bool = True,
        reason: str = 'pipeline_error',
    ) -> None:
        super().__init__(message)
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.retryable = retryable
        self.reason = reason


class ScanPipelineService:
    def __init__(self) -> None:
        self.nmap_runner = NmapRunner()
        self.nmap_parser = NmapXmlParser()
        self.external_runner = ExternalToolRunner()

    def execute(self, scan: ScanExecution) -> ScanPipelineResult:
        requested_scan_type = (scan.engine_metadata or {}).get('requested_scan_type') or 'nmap_discovery'
        if requested_scan_type in INFRA_SCAN_TYPES:
            return self._run_infra_pipeline(scan, requested_scan_type)
        if requested_scan_type in WEB_SCAN_TYPES:
            return self._run_web_pipeline(scan, requested_scan_type)
        return self._run_infra_pipeline(scan, 'nmap_discovery')

    def _run_infra_pipeline(self, scan: ScanExecution, scan_type: str) -> ScanPipelineResult:
        profile = NMAP_PROFILE_BY_SCAN_TYPE.get(scan_type, 'discovery')
        run_result = self.nmap_runner.run(target=scan.asset.value, profile=profile)
        parsed_output, parse_metadata = self._parse_infra_output(run_result.xml_output)
        has_partial_data = bool(parsed_output.hosts)
        timed_out = bool((run_result.metadata or {}).get('timed_out'))
        if run_result.return_code != 0 and not has_partial_data:
            timeout_message = (
                f'Infrastructure scan timed out for profile "{profile}" '
                f'after {(run_result.metadata or {}).get("timeout_seconds")} seconds.'
            )
            raise ScanPipelineExecutionError(
                timeout_message if timed_out else (run_result.stderr or 'Nmap returned non-zero exit status'),
                command=run_result.command,
                stdout=run_result.stdout,
                stderr=run_result.stderr,
                retryable=not timed_out,
                reason='nmap_timeout' if timed_out else 'nmap_runtime_error',
            )

        with transaction.atomic():
            for parsed_host in parsed_output.hosts:
                RawEvidence.objects.create(
                    organization=scan.organization,
                    scan_execution=scan,
                    source='nmap',
                    host=parsed_host.host,
                    payload=parsed_host.model_dump(),
                    raw_output=run_result.xml_output,
                    metadata={
                        'stderr': run_result.stderr,
                        'stdout': run_result.stdout,
                        'scan_type': scan_type,
                        'partial_result': timed_out or bool(parse_metadata.get('recovered_partial_xml')),
                    },
                )
                for parsed_service in parsed_host.ports:
                    raw_version = parsed_service.version
                    ServiceFinding.objects.create(
                        organization=scan.organization,
                        scan_execution=scan,
                        host=parsed_host.host,
                        port=parsed_service.port,
                        protocol=parsed_service.protocol,
                        state=parsed_service.state,
                        service=parsed_service.service,
                        product=parsed_service.product,
                        version=raw_version,
                        raw_version=raw_version,
                        normalized_version=normalize_version(raw_version),
                        extrainfo=parsed_service.extrainfo,
                        banner=parsed_service.banner,
                        scripts=[vars(script) for script in parsed_service.scripts],
                    )

        summary = {
            'scan_type': scan_type,
            'category': 'infra',
            'hosts': len(parsed_output.hosts),
            'services': scan.service_findings.count(),
            'tools': ['nmap'],
            'partial_result': timed_out or bool(parse_metadata.get('recovered_partial_xml')),
        }
        metadata = {
            'pipeline': 'infra',
            'modules': {
                'nmap': {
                    'profile': profile,
                    'return_code': run_result.return_code,
                    'stderr': run_result.stderr,
                    'stdout': run_result.stdout,
                    'command': run_result.command,
                    'parse': parse_metadata,
                    **(run_result.metadata or {}),
                }
            },
        }
        return ScanPipelineResult(summary=summary, command_executed=run_result.command, engine_metadata=metadata)

    def _parse_infra_output(self, xml_output: str) -> tuple[Any, dict[str, Any]]:
        parse_metadata: dict[str, Any] = {'recovered_partial_xml': False}
        if not xml_output.strip():
            return self.nmap_parser.parse('<nmaprun></nmaprun>'), parse_metadata

        try:
            return self.nmap_parser.parse(xml_output), parse_metadata
        except ET.ParseError:
            recovered_xml = self._recover_partial_nmap_xml(xml_output)
            if recovered_xml:
                parse_metadata['recovered_partial_xml'] = True
                return self.nmap_parser.parse(recovered_xml), parse_metadata
            raise

    def _recover_partial_nmap_xml(self, xml_output: str) -> str:
        if '<nmaprun' not in xml_output:
            return ''

        root_match = re.search(r'<nmaprun[^>]*>', xml_output)
        if not root_match:
            return ''

        host_blocks = re.findall(r'<host(?:\s[^>]*)?>.*?</host>', xml_output, flags=re.DOTALL)
        if not host_blocks:
            return ''

        return f"{root_match.group(0)}{''.join(host_blocks)}</nmaprun>"

    def _run_web_pipeline(self, scan: ScanExecution, scan_type: str) -> ScanPipelineResult:
        target = scan.asset.value
        modules: dict[str, Any] = {}
        tools_used: list[str] = []
        technologies: set[str] = set()
        endpoints: list[dict[str, Any]] = []
        vulnerabilities: list[dict[str, Any]] = []
        headers: dict[str, str] = {}
        cms = ''

        # 1) Fingerprinting
        whatweb = self.external_runner.run('whatweb', ['--log-json=-', target])
        modules['whatweb'] = vars(whatweb)
        tools_used.append('whatweb')
        ww_payload = parse_whatweb_json(whatweb.stdout)
        plugins = ww_payload.get('plugins') if isinstance(ww_payload, dict) else {}
        if isinstance(plugins, dict):
            technologies.update(plugins.keys())
            if 'HTTPServer' in plugins and isinstance(plugins['HTTPServer'], dict):
                headers.update(plugins['HTTPServer'])
        RawEvidence.objects.create(
            organization=scan.organization,
            scan_execution=scan,
            source='whatweb',
            host=target,
            payload=ww_payload,
            raw_output=whatweb.stdout,
            metadata={'stderr': whatweb.stderr, 'command': whatweb.command, 'scan_type': scan_type},
        )

        # 2) Enumeración
        enum_tool = 'ffuf' if scan_type in {'web_api', 'web_full'} else 'gobuster'
        if enum_tool == 'ffuf':
            enum_res = self.external_runner.run('ffuf', ['-u', f'{target}/FUZZ', '-w', '/usr/share/wordlists/dirb/common.txt', '-json'])
            endpoints = []
            # fallback parsing for ffuf json-lines
            for row in [r for r in enum_res.stdout.splitlines() if r.strip().startswith('{')]:
                try:
                    import json

                    obj = json.loads(row)
                    endpoints.append({'path': obj.get('url', ''), 'status_code': obj.get('status')})
                except Exception:
                    continue
        else:
            enum_res = self.external_runner.run('gobuster', ['dir', '-u', target, '-w', '/usr/share/wordlists/dirb/common.txt', '-o', '/dev/stdout', '--format', 'json'])
            endpoints = parse_gobuster_json(enum_res.stdout)
        modules[enum_tool] = vars(enum_res)
        tools_used.append(enum_tool)
        RawEvidence.objects.create(
            organization=scan.organization,
            scan_execution=scan,
            source=enum_tool,
            host=target,
            payload={'endpoints': endpoints},
            raw_output=enum_res.stdout,
            metadata={'stderr': enum_res.stderr, 'command': enum_res.command, 'scan_type': scan_type},
        )

        # 3) Vulnerabilidades (nuclei obligatorio)
        nuclei_res = self.external_runner.run('nuclei', ['-u', target, '-jsonl', '-silent'])
        modules['nuclei'] = vars(nuclei_res)
        tools_used.append('nuclei')
        if nuclei_res.missing_binary:
            raise RuntimeError('Nuclei es obligatorio para escaneos web y no está instalado en el worker.')
        vulnerabilities.extend(parse_nuclei_json(nuclei_res.stdout))

        nikto_res = self.external_runner.run('nikto', ['-h', target, '-Format', 'txt'])
        modules['nikto'] = vars(nikto_res)
        tools_used.append('nikto')
        vulnerabilities.extend(parse_nikto_text(nikto_res.stdout))

        RawEvidence.objects.create(
            organization=scan.organization,
            scan_execution=scan,
            source='nuclei',
            host=target,
            payload={'vulnerabilities': vulnerabilities},
            raw_output=nuclei_res.stdout,
            metadata={'stderr': nuclei_res.stderr, 'command': nuclei_res.command, 'scan_type': scan_type},
        )

        RawEvidence.objects.create(
            organization=scan.organization,
            scan_execution=scan,
            source='nikto',
            host=target,
            payload={'vulnerabilities': [v for v in vulnerabilities if v.get('type') == 'nikto']},
            raw_output=nikto_res.stdout,
            metadata={'stderr': nikto_res.stderr, 'command': nikto_res.command, 'scan_type': scan_type},
        )

        # 4) CMS detection + WordPress
        tech_lc = {t.lower() for t in technologies}
        wordpress_detected = ('wordpress' in tech_lc) or (scan_type in {'web_wordpress', 'wordpress_scan'})
        if wordpress_detected:
            cms = 'wordpress'
            wp_res = self.external_runner.run('wpscan', ['--url', target, '--format', 'json', '--no-update'])
            modules['wpscan'] = vars(wp_res)
            tools_used.append('wpscan')
            wp_payload = parse_wpscan_json(wp_res.stdout)
            wp_vulns = wp_payload.get('version', {}).get('vulnerabilities', []) if isinstance(wp_payload, dict) else []
            for vuln in wp_vulns:
                vulnerabilities.append(
                    {
                        'name': vuln.get('title', 'WordPress vulnerability'),
                        'severity': 'high',
                        'description': vuln.get('title', ''),
                        'reference': (vuln.get('references', {}).get('url') or [''])[0],
                        'type': 'wpscan',
                    }
                )
            RawEvidence.objects.create(
                organization=scan.organization,
                scan_execution=scan,
                source='wpscan',
                host=target,
                payload=wp_payload,
                raw_output=wp_res.stdout,
                metadata={'stderr': wp_res.stderr, 'command': wp_res.command, 'scan_type': scan_type},
            )

        with transaction.atomic():
            host, port = url_host_port(target)
            # service finding for correlation rules (e.g. wordpress/php/http)
            for tech in sorted(technologies):
                ServiceFinding.objects.get_or_create(
                    organization=scan.organization,
                    scan_execution=scan,
                    host=host,
                    port=port,
                    protocol='tcp',
                    service='http' if port in {80, 8080} else 'https',
                    product=tech,
                    defaults={
                        'state': 'open',
                        'version': '',
                        'raw_version': '',
                        'normalized_version': '',
                        'extrainfo': '',
                        'banner': '',
                        'scripts': [],
                    },
                )

            for endpoint in endpoints:
                WebFinding.objects.create(
                    organization=scan.organization,
                    scan_execution=scan,
                    host=host,
                    url=f"{target.rstrip('/')}/{str(endpoint.get('path', '')).lstrip('/')}",
                    title='Endpoint discovered',
                    technology='',
                    evidence=str(endpoint),
                    metadata={'module': 'enumeration', 'status_code': endpoint.get('status_code')},
                )

            for tech in sorted(technologies):
                WebFinding.objects.create(
                    organization=scan.organization,
                    scan_execution=scan,
                    host=host,
                    url=target,
                    title='Technology detected',
                    technology=tech,
                    evidence=tech,
                    metadata={'module': 'fingerprinting', 'headers': headers},
                )

            for vuln in vulnerabilities:
                sev = (vuln.get('severity') or 'medium').lower()
                if sev not in dict(Finding.Severity.choices):
                    sev = Finding.Severity.MEDIUM
                Finding.objects.get_or_create(
                    organization=scan.organization,
                    scan_execution=scan,
                    asset=scan.asset,
                    title=vuln.get('name') or 'Web vulnerability',
                    defaults={
                        'description': vuln.get('description', ''),
                        'remediation': 'Validar el hallazgo y aplicar actualización/configuración recomendada.',
                        'reference': vuln.get('reference', ''),
                        'severity': sev,
                        'confidence': Finding.Confidence.MEDIUM,
                        'status': Finding.Status.OPEN,
                    },
                )

        summary = {
            'scan_type': scan_type,
            'category': 'web',
            'tools': tools_used,
            'technologies_count': len(technologies),
            'endpoints_count': len(endpoints),
            'vulnerabilities_count': len(vulnerabilities),
            'cms': cms,
        }
        metadata = {
            'pipeline': 'web',
            'modules': modules,
            'structured_results': {
                'technologies': sorted(technologies),
                'endpoints': endpoints,
                'vulnerabilities': vulnerabilities,
                'headers': headers,
                'cms': cms,
            },
        }
        command_executed = ' && '.join(
            module['command'] for module in modules.values() if isinstance(module, dict) and module.get('command')
        )
        return ScanPipelineResult(summary=summary, command_executed=command_executed, engine_metadata=metadata)
