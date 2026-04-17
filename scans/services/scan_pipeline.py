from __future__ import annotations

import json
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
        try:
            parsed_output, parse_metadata = self._parse_infra_output(run_result.xml_output)
        except ET.ParseError as exc:
            raise ScanPipelineExecutionError(
                f'No se pudo parsear la salida XML de Nmap para el perfil "{profile}" '
                f'(salida incompleta o inválida no recuperable): {exc}',
                command=run_result.command,
                stdout=self._coerce_xml_text(run_result.stdout),
                stderr=run_result.stderr,
                retryable=False,
                reason='nmap_parse_error',
            ) from exc
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
                    raw_version = ' '.join(
                        part.strip() for part in [parsed_service.version, parsed_service.extrainfo] if part and part.strip()
                    ).strip()
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

    def _parse_infra_output(self, xml_output: str | bytes | None) -> tuple[Any, dict[str, Any]]:
        parse_metadata: dict[str, Any] = {'recovered_partial_xml': False}
        xml_text = self._coerce_xml_text(xml_output)
        if not xml_text.strip():
            return self.nmap_parser.parse('<nmaprun></nmaprun>'), parse_metadata

        try:
            return self.nmap_parser.parse(xml_text), parse_metadata
        except ET.ParseError:
            recovered_xml = self._recover_partial_nmap_xml(xml_text)
            if recovered_xml:
                parse_metadata['recovered_partial_xml'] = True
                return self.nmap_parser.parse(recovered_xml), parse_metadata
            raise

    def _coerce_xml_text(self, xml_output: str | bytes | None) -> str:
        if xml_output is None:
            return ''
        if isinstance(xml_output, bytes):
            return xml_output.decode('utf-8', errors='replace')
        return str(xml_output)

    def _recover_partial_nmap_xml(self, xml_output: str | bytes | None) -> str:
        xml_text = self._coerce_xml_text(xml_output)
        if not xml_text.strip():
            return ''
        xml_text = xml_text.replace('\x00', '')

        if '</nmaprun>' in xml_text:
            candidate = xml_text
            if '<host' in xml_text and '</host>' not in xml_text:
                host_blocks = re.findall(r'<host(?:\s[^>]*)?>.*?</host>', xml_text, flags=re.DOTALL)
                root_match = re.search(r'<nmaprun[^>]*>', xml_text)
                if root_match and host_blocks:
                    candidate = f"{root_match.group(0)}{''.join(host_blocks)}</nmaprun>"
            try:
                ET.fromstring(candidate)
                return candidate
            except ET.ParseError:
                pass

        if '<nmaprun' not in xml_text:
            return ''

        root_match = re.search(r'<nmaprun[^>]*>', xml_text)
        if not root_match:
            return ''

        host_blocks = re.findall(r'<host(?:\s[^>]*)?>.*?</host>', xml_text, flags=re.DOTALL)
        if not host_blocks:
            return ''

        recovered = f"{root_match.group(0)}{''.join(host_blocks)}</nmaprun>"
        try:
            ET.fromstring(recovered)
            return recovered
        except ET.ParseError:
            return ''

    def _run_web_pipeline(self, scan: ScanExecution, scan_type: str) -> ScanPipelineResult:
        target = scan.asset.value
        modules: dict[str, Any] = {}
        tools_executed: list[str] = []
        tools_skipped: list[dict[str, Any]] = []
        warnings: list[str] = []
        technologies: set[str] = set()
        endpoints: list[dict[str, Any]] = []
        vulnerabilities: list[dict[str, Any]] = []
        headers: dict[str, str] = {}
        cms = ''
        fingerprint_detected = False

        def _record_module(tool_name: str, result: Any, *, required: bool = False) -> bool:
            modules[tool_name] = vars(result)
            if result.missing_binary:
                reason = f'Binary {tool_name} no disponible en worker.'
                if required:
                    warnings.append(f'[requerido] {reason}')
                else:
                    warnings.append(reason)
                tools_skipped.append({'tool': tool_name, 'reason': 'missing_binary', 'required': required})
                return False
            tools_executed.append(tool_name)
            if result.timed_out:
                warnings.append(f'{tool_name} excedió el timeout configurado.')
            elif result.return_code != 0:
                warnings.append(f'{tool_name} terminó con código {result.return_code}.')
            return True

        # 1) Fingerprinting
        whatweb = self.external_runner.run('whatweb', ['--log-json=-', target])
        if _record_module('whatweb', whatweb):
            ww_payload = parse_whatweb_json(whatweb.stdout)
            plugins = ww_payload.get('plugins') if isinstance(ww_payload, dict) else {}
            if isinstance(plugins, dict):
                technologies.update(plugins.keys())
                fingerprint_detected = bool(plugins)
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
        enum_args = (
            ['-u', f'{target}/FUZZ', '-w', '/usr/share/wordlists/dirb/common.txt', '-json']
            if enum_tool == 'ffuf'
            else ['dir', '-u', target, '-w', '/usr/share/wordlists/dirb/common.txt', '-o', '/dev/stdout', '--format', 'json']
        )
        enum_res = self.external_runner.run(enum_tool, enum_args)
        if _record_module(enum_tool, enum_res):
            if enum_tool == 'ffuf':
                for row in [r for r in enum_res.stdout.splitlines() if r.strip().startswith('{')]:
                    try:
                        obj = json.loads(row)
                        endpoints.append({'path': obj.get('url', ''), 'status_code': obj.get('status')})
                    except json.JSONDecodeError:
                        continue
            else:
                endpoints = parse_gobuster_json(enum_res.stdout)
            RawEvidence.objects.create(
                organization=scan.organization,
                scan_execution=scan,
                source=enum_tool,
                host=target,
                payload={'endpoints': endpoints},
                raw_output=enum_res.stdout,
                metadata={'stderr': enum_res.stderr, 'command': enum_res.command, 'scan_type': scan_type},
            )

        # 3) Vulnerabilidades
        nuclei_required = scan_type == 'web_full'
        nuclei_res = self.external_runner.run('nuclei', ['-u', target, '-jsonl', '-silent'])
        if _record_module('nuclei', nuclei_res, required=nuclei_required):
            vulnerabilities.extend(parse_nuclei_json(nuclei_res.stdout))
            RawEvidence.objects.create(
                organization=scan.organization,
                scan_execution=scan,
                source='nuclei',
                host=target,
                payload={'vulnerabilities': [v for v in vulnerabilities if v.get('type') == 'nuclei']},
                raw_output=nuclei_res.stdout,
                metadata={'stderr': nuclei_res.stderr, 'command': nuclei_res.command, 'scan_type': scan_type},
            )

        nikto_res = self.external_runner.run('nikto', ['-h', target, '-Format', 'txt'])
        if _record_module('nikto', nikto_res):
            vulnerabilities.extend(parse_nikto_text(nikto_res.stdout))
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
            if _record_module('wpscan', wp_res, required=scan_type in {'web_wordpress', 'wordpress_scan'}):
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

        if not tools_executed:
            raise ScanPipelineExecutionError(
                'No hay herramientas web disponibles en el worker para ejecutar este escaneo.',
                retryable=False,
                reason='web_no_tools_available',
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
            'tools': tools_executed,
            'tools_executed': tools_executed,
            'tools_skipped': tools_skipped,
            'warnings': warnings,
            'partial_result': bool(tools_skipped or warnings),
            'technologies_count': len(technologies),
            'endpoints_count': len(endpoints),
            'vulnerabilities_count': len(vulnerabilities),
            'cms': cms,
        }
        metadata = {
            'pipeline': 'web',
            'modules': modules,
            'structured_results': {
                'scan_type': scan_type,
                'technologies': sorted(technologies),
                'endpoints': endpoints,
                'vulnerabilities': vulnerabilities,
                'headers': headers,
                'cms': cms,
                'tools_executed': tools_executed,
                'tools_skipped': tools_skipped,
                'warnings': warnings,
                'partial_result': bool(tools_skipped or warnings),
                'fingerprint_detected': fingerprint_detected,
            },
        }
        command_executed = ' && '.join(
            module['command'] for module in modules.values() if isinstance(module, dict) and module.get('command')
        )
        return ScanPipelineResult(summary=summary, command_executed=command_executed, engine_metadata=metadata)
