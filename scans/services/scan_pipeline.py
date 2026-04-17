from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from django.db import transaction

from findings.models import Finding
from integrations.parsers.nmap_parser import NmapXmlParser
from integrations.runners.nmap_runner import NmapRunner
from scans.engines.tooling import ExternalToolRunner, ToolExecutionResult
from scans.models import RawEvidence, ScanExecution, ServiceFinding, WebFinding
from scans.parsers.web_parsers import (
    parse_ffuf_output,
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

HEADER_INTERPRETATION_RULES = {
    'x-frame-options': {
        'title': 'Protección anti-clickjacking',
        'ok_when_present': True,
        'ok_description': 'Header presente: ayuda a mitigar iframes maliciosos.',
        'warning_description': 'Header ausente: existe riesgo de clickjacking.',
    },
    'x-content-type-options': {
        'title': 'Protección MIME sniffing',
        'ok_when_present': True,
        'ok_description': 'Header presente: evita interpretación MIME insegura.',
        'warning_description': 'Header ausente: el navegador puede inferir tipos MIME incorrectos.',
    },
    'strict-transport-security': {
        'title': 'Forzado de HTTPS (HSTS)',
        'ok_when_present': True,
        'ok_description': 'Header presente: refuerza uso de HTTPS.',
        'warning_description': 'Header ausente: no hay política HSTS anunciada.',
    },
    'content-security-policy': {
        'title': 'Política de seguridad de contenido (CSP)',
        'ok_when_present': True,
        'ok_description': 'Header presente: ayuda a reducir riesgo XSS.',
        'warning_description': 'Header ausente: sin política CSP explícita.',
    },
    'server': {
        'title': 'Exposición tecnológica por Server',
        'ok_when_present': False,
        'ok_description': 'Header oculto: menor exposición de fingerprinting.',
        'warning_description': 'Header expuesto: revela stack/tecnología del servidor.',
    },
    'x-powered-by': {
        'title': 'Exposición tecnológica por X-Powered-By',
        'ok_when_present': False,
        'ok_description': 'Header oculto: menor exposición de framework/backend.',
        'warning_description': 'Header expuesto: revela tecnología de backend.',
    },
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
        raw_target = scan.asset.value
        modules: dict[str, Any] = {}
        tools_executed: list[str] = []
        tools_failed: list[dict[str, Any]] = []
        tools_skipped: list[dict[str, Any]] = []
        warnings: list[str] = []
        dependency_checks: dict[str, Any] = {}
        tools_available: list[str] = []
        technologies: set[str] = set()
        endpoints: list[dict[str, Any]] = []
        vulnerabilities: list[dict[str, Any]] = []
        headers: dict[str, str] = {}
        interpreted_headers: list[dict[str, Any]] = []
        cms = ''
        fingerprint_detected = False

        normalized_target, probe_result = self._resolve_web_target(raw_target)
        target = normalized_target
        headers.update(probe_result.get('headers') or {})
        modules['http_probe'] = probe_result
        if not probe_result.get('ok'):
            raise ScanPipelineExecutionError(
                f'El target web "{raw_target}" no respondió por HTTP(S) tras normalización.',
                command=probe_result.get('command', ''),
                stdout='',
                stderr=probe_result.get('error', ''),
                retryable=False,
                reason='web_target_unreachable',
            )

        tool_presence = {
            'whatweb': self.external_runner.is_available('whatweb'),
            'nuclei': self.external_runner.is_available('nuclei'),
            'gobuster': self.external_runner.is_available('gobuster'),
            'ffuf': self.external_runner.is_available('ffuf'),
            'nikto': self.external_runner.is_available('nikto'),
            'wpscan': self.external_runner.is_available('wpscan'),
        }
        dependency_checks = {
            'whatweb': {'available': tool_presence['whatweb'], 'required': True},
            'nuclei': {'available': tool_presence['nuclei'], 'required': scan_type == 'web_full'},
            'gobuster': {'available': tool_presence['gobuster'], 'required': False},
            'ffuf': {'available': tool_presence['ffuf'], 'required': False},
            'gobuster_or_ffuf': {
                'available': tool_presence['gobuster'] or tool_presence['ffuf'],
                'required': True,
            },
            'nikto': {'available': tool_presence['nikto'], 'required': False},
            'wpscan': {'available': tool_presence['wpscan'], 'required': scan_type in {'web_wordpress', 'wordpress_scan'}},
        }
        tools_available = sorted([tool for tool, is_available in tool_presence.items() if is_available])

        if not dependency_checks['nikto']['available']:
            warnings.append('Nikto no disponible: se omite escaneo nikto (opcional).')

        def _record_module(tool_name: str, result: Any, *, required: bool = False) -> bool:
            modules[tool_name] = self._serialize_module_result(result, required=required)
            if result.missing_binary:
                reason = f'Binary {tool_name} no disponible en worker.'
                if required:
                    warnings.append(f'[requerido] {reason}')
                else:
                    warnings.append(reason)
                tools_skipped.append({'tool': tool_name, 'reason': 'missing_binary', 'required': required})
                return False
            if result.timed_out:
                tools_failed.append(
                    {
                        'tool': tool_name,
                        'return_code': result.return_code,
                        'timed_out': True,
                        'stderr': self._summarize_output(result.stderr, 240),
                    }
                )
                warnings.append(f'{tool_name} excedió el timeout configurado. {self._summarize_output(result.stderr, 180)}')
                return False
            elif result.return_code != 0:
                details = self._summarize_output(result.stderr or result.stdout, 220)
                tools_failed.append(
                    {
                        'tool': tool_name,
                        'return_code': result.return_code,
                        'timed_out': False,
                        'stderr': self._summarize_output(result.stderr, 240),
                    }
                )
                warnings.append(f'{tool_name} terminó con código {result.return_code}. Detalle: {details or "sin stderr"}')
                return False
            tools_executed.append(tool_name)
            return True

        # 1) Fingerprinting
        whatweb = self.run_whatweb(target)
        if _record_module('whatweb', whatweb, required=True):
            ww_payload = parse_whatweb_json(whatweb.stdout)
            plugins = self._extract_whatweb_plugins(ww_payload)
            fingerprint = self._build_whatweb_fingerprint(ww_payload, target)
            if isinstance(plugins, dict):
                technologies.update(plugins.keys())
                fingerprint_detected = bool(plugins)
                if 'HTTPServer' in plugins:
                    headers['Server'] = self._extract_plugin_text(plugins.get('HTTPServer'))
                if 'X-Powered-By' in plugins:
                    headers['X-Powered-By'] = self._extract_plugin_text(plugins.get('X-Powered-By'))
                if 'WordPress' in plugins:
                    cms = 'wordpress'
            if not fingerprint_detected and (whatweb.stdout or whatweb.stderr):
                warnings.append(
                    'WhatWeb no identificó plugins claros; revisar salida técnica en metadata del módulo whatweb.'
                )
            interpreted_headers = self._interpret_headers(headers)
            RawEvidence.objects.create(
                organization=scan.organization,
                scan_execution=scan,
                source='whatweb',
                host=target,
                payload=ww_payload,
                raw_output=whatweb.stdout,
                metadata={'stderr': whatweb.stderr, 'command': whatweb.command, 'scan_type': scan_type},
            )
        else:
            fingerprint = {}

        # 2) Enumeración
        preferred_enum_tool = 'ffuf' if scan_type in {'web_api', 'web_full'} else 'gobuster'
        fallback_enum_tool = 'gobuster' if preferred_enum_tool == 'ffuf' else 'ffuf'
        enum_tool = preferred_enum_tool
        skip_enumeration = False
        if not tool_presence.get(preferred_enum_tool) and tool_presence.get(fallback_enum_tool):
            enum_tool = fallback_enum_tool
            warnings.append(
                f'{preferred_enum_tool} no disponible; se usa {fallback_enum_tool} como fallback para enumeración web.'
            )
        elif not tool_presence.get(preferred_enum_tool) and not tool_presence.get(fallback_enum_tool):
            warnings.append('No hay herramienta de enumeración disponible (ffuf/gobuster); se omite esa fase.')
            tools_skipped.append({'tool': preferred_enum_tool, 'reason': 'missing_binary', 'required': False})
            tools_skipped.append({'tool': fallback_enum_tool, 'reason': 'missing_binary', 'required': False})
            skip_enumeration = True
        if not skip_enumeration:
            wordlist, wordlist_warning = self._resolve_wordlist()
            if wordlist_warning:
                warnings.append(wordlist_warning)
            if wordlist:
                enum_res = self.run_ffuf(target, wordlist) if enum_tool == 'ffuf' else self.run_gobuster(target, wordlist)
                enum_ok = _record_module(enum_tool, enum_res)
                if not enum_ok and tool_presence.get(fallback_enum_tool) and fallback_enum_tool != enum_tool:
                    warnings.append(
                        f'{enum_tool} falló; se intenta fallback con {fallback_enum_tool}.'
                    )
                    fallback_result = (
                        self.run_ffuf(target, wordlist)
                        if fallback_enum_tool == 'ffuf'
                        else self.run_gobuster(target, wordlist)
                    )
                    enum_ok = _record_module(fallback_enum_tool, fallback_result)
                    enum_tool = fallback_enum_tool
                    enum_res = fallback_result
                if enum_ok:
                    if enum_tool == 'ffuf':
                        endpoints = parse_ffuf_output(enum_res.stdout)
                    else:
                        endpoints = parse_gobuster_json(enum_res.stdout)
                    endpoints = self._dedupe_endpoints(target, endpoints)
                    RawEvidence.objects.create(
                        organization=scan.organization,
                        scan_execution=scan,
                        source=enum_tool,
                        host=target,
                        payload={'endpoints': endpoints},
                        raw_output=enum_res.stdout,
                        metadata={
                            'stderr': enum_res.stderr,
                            'stdout_excerpt': self._summarize_output(enum_res.stdout, 400),
                            'command': enum_res.command,
                            'scan_type': scan_type,
                            'wordlist': wordlist,
                        },
                    )
            else:
                modules[enum_tool] = {
                    'tool': enum_tool,
                    'command': '',
                    'return_code': 0,
                    'stdout': '',
                    'stderr': 'Missing wordlist',
                    'stdout_excerpt': '',
                    'stderr_excerpt': 'Missing wordlist',
                    'timed_out': False,
                    'missing_binary': False,
                    'skipped': True,
                    'reason': 'missing_wordlist',
                    'state': 'skipped',
                }
                warnings.append(f'Se omite {enum_tool}: no se encontró wordlist para enumeración.')
                tools_skipped.append({'tool': enum_tool, 'reason': 'missing_wordlist', 'required': False})

        interpreted_headers = self._interpret_headers(headers)

        # 3) Vulnerabilidades
        nuclei_required = scan_type == 'web_full'
        nuclei_templates = self._resolve_nuclei_templates()
        if not nuclei_templates:
            warnings.append(
                f'No se encontraron templates de nuclei en rutas esperadas ({", ".join(self._nuclei_template_candidates())}); se omite.'
            )
            tools_skipped.append({'tool': 'nuclei', 'reason': 'missing_templates', 'required': nuclei_required})
            nuclei_res = self._missing_dependency_result(
                'nuclei',
                f'No nuclei templates found in: {", ".join(self._nuclei_template_candidates())}',
            )
        else:
            nuclei_res = self.run_nuclei(target, nuclei_templates)
        if _record_module('nuclei', nuclei_res, required=nuclei_required):
            vulnerabilities.extend(parse_nuclei_json(nuclei_res.stdout))
            RawEvidence.objects.create(
                organization=scan.organization,
                scan_execution=scan,
                source='nuclei',
                host=target,
                payload={'vulnerabilities': [v for v in vulnerabilities if v.get('type') == 'nuclei']},
                raw_output=nuclei_res.stdout,
                    metadata={
                        'stderr': nuclei_res.stderr,
                        'command': nuclei_res.command,
                        'scan_type': scan_type,
                        'templates_path': str(nuclei_templates),
                    },
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
            if not tool_presence.get('wpscan'):
                warnings.append(
                    'WordPress detectado, pero WPScan no está disponible; se omite el escaneo específico de WordPress.'
                )
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

        vulnerabilities = self._dedupe_vulnerabilities(vulnerabilities)

        if not tools_executed:
            warnings.append('No hubo herramientas externas exitosas; se devuelve resultado parcial usando HTTP probe/headers.')

        with transaction.atomic():
            host, port = url_host_port(target)
            ServiceFinding.objects.get_or_create(
                organization=scan.organization,
                scan_execution=scan,
                host=host,
                port=port,
                protocol='tcp',
                service='http' if port in {80, 8080} else 'https',
                defaults={
                    'state': 'open',
                    'product': headers.get('Server', '')[:120],
                    'version': '',
                    'raw_version': '',
                    'normalized_version': '',
                    'extrainfo': '',
                    'banner': '',
                    'scripts': [],
                },
            )

            for endpoint in endpoints:
                endpoint_path = str(endpoint.get('path', '')).strip() or '/'
                endpoint_url = str(endpoint.get('url') or f"{target.rstrip('/')}/{endpoint_path.lstrip('/')}")
                WebFinding.objects.get_or_create(
                    organization=scan.organization,
                    scan_execution=scan,
                    host=host,
                    url=endpoint_url,
                    title='Endpoint discovered',
                    technology='',
                    evidence=f"{endpoint_path} [{endpoint.get('status_code') or 'n/a'}]",
                    metadata={'module': 'enumeration', **endpoint},
                )

            for tech in sorted(technologies):
                WebFinding.objects.get_or_create(
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

            for header_finding in interpreted_headers:
                WebFinding.objects.get_or_create(
                    organization=scan.organization,
                    scan_execution=scan,
                    host=host,
                    url=target,
                    title=f"Header: {header_finding['header']}",
                    technology='',
                    evidence=f"{header_finding['status']} · {header_finding['message']}",
                    metadata={'module': 'http_headers', **header_finding},
                )

        summary = {
            'scan_type': scan_type,
            'category': 'web',
            'tools': tools_executed,
            'tools_available': tools_available,
            'tools_executed': tools_executed,
            'tools_failed': tools_failed,
            'tools_skipped': tools_skipped,
            'dependency_checks': dependency_checks,
            'warnings': warnings,
            'partial_result': bool(tools_skipped or warnings),
            'technologies_count': len(technologies),
            'endpoints_count': len(endpoints),
            'vulnerabilities_count': len(vulnerabilities),
            'interpreted_headers_count': len(interpreted_headers),
            'cms': cms,
            'target': target,
        }
        tools_map = {
            'available': tools_available,
            'executed': tools_executed,
            'failed': tools_failed,
            'skipped': tools_skipped,
            'dependency_checks': dependency_checks,
        }
        http_status = probe_result.get('status_code')
        redirections = fingerprint.get('redirections') or []
        web_basic_findings = self._build_basic_web_findings(endpoints=endpoints, headers_analysis=self._group_interpreted_headers(interpreted_headers))
        metadata = {
            'pipeline': 'web',
            'modules': modules,
            'structured_results': {
                'target': target,
                'target_url': target,
                'http_status': http_status,
                'redirects': redirections,
                'http_probe': probe_result,
                'scan_type': scan_type,
                'technologies': sorted(technologies),
                'endpoints': endpoints,
                'web_findings_basic': web_basic_findings,
                'vulnerabilities': vulnerabilities,
                'headers': headers,
                'interpreted_headers': interpreted_headers,
                'cms': cms,
                'fingerprint': fingerprint,
                'tools': tools_map,
                'tools_available': tools_available,
                'tools_executed': tools_executed,
                'tools_failed': tools_failed,
                'tools_skipped': tools_skipped,
                'dependency_checks': dependency_checks,
                'warnings': warnings,
                'partial_result': bool(tools_skipped or warnings),
                'fingerprint_detected': fingerprint_detected,
                'headers_analysis': self._group_interpreted_headers(interpreted_headers),
            },
        }
        command_executed = '; '.join(
            module['command'] for module in modules.values() if isinstance(module, dict) and module.get('command')
        )
        return ScanPipelineResult(summary=summary, command_executed=command_executed, engine_metadata=metadata)

    def _resolve_web_target(self, raw_target: str) -> tuple[str, dict[str, Any]]:
        candidate_urls: list[str]
        parsed = urlparse(raw_target)
        if parsed.scheme:
            candidate_urls = [raw_target]
        else:
            stripped = raw_target.strip().strip('/')
            candidate_urls = [f'https://{stripped}', f'http://{stripped}']

        errors: list[str] = []
        for url in candidate_urls:
            probe = self._probe_http_target(url)
            if probe['ok']:
                return url, probe
            errors.append(f'{url}: {probe.get("error", "unknown error")}')

        return candidate_urls[0], {
            'ok': False,
            'status_code': None,
            'headers': {},
            'error': '; '.join(errors),
            'command': f'http_probe {", ".join(candidate_urls)}',
        }

    def _probe_http_target(self, target: str, timeout: int = 8) -> dict[str, Any]:
        user_agent = {'User-Agent': 'ULTRISCAN/1.0'}
        for method in ('HEAD', 'GET'):
            req = request.Request(target, method=method, headers=user_agent)
            try:
                with request.urlopen(req, timeout=timeout) as response:
                    return {
                        'ok': True,
                        'method': method,
                        'status_code': response.getcode(),
                        'headers': {k: v for k, v in response.headers.items()},
                        'error': '',
                        'command': f'HTTP {method} {target}',
                    }
            except HTTPError as exc:
                return {
                    'ok': True,
                    'method': method,
                    'status_code': exc.code,
                    'headers': {k: v for k, v in exc.headers.items()} if exc.headers else {},
                    'error': f'HTTP {exc.code}',
                    'command': f'HTTP {method} {target}',
                }
            except URLError as exc:
                error = str(exc.reason)
            except Exception as exc:  # noqa: BLE001
                error = str(exc)
            if method == 'GET':
                return {
                    'ok': False,
                    'method': method,
                    'status_code': None,
                    'headers': {},
                    'error': error,
                    'command': f'HTTP {method} {target}',
                }
        return {'ok': False, 'method': 'GET', 'status_code': None, 'headers': {}, 'error': 'probe failed', 'command': ''}

    def run_whatweb(self, target: str):
        return self.external_runner.run('whatweb', ['--log-json=-', target])

    def run_gobuster(self, target: str, wordlist: str):
        return self.external_runner.run(
            'gobuster',
            [
                'dir',
                '-u',
                target,
                '-w',
                wordlist,
                '--no-error',
                '--no-color',
                '-k',
                '-q',
            ],
        )

    def run_ffuf(self, target: str, wordlist: str):
        return self.external_runner.run(
            'ffuf',
            [
                '-u',
                f'{target.rstrip("/")}/FUZZ',
                '-w',
                wordlist,
                '-json',
                '-mc',
                '200,204,301,302,307,401,403',
            ],
        )

    def run_nuclei(self, target: str, templates_path: Path):
        return self.external_runner.run(
            'nuclei',
            [
                '-u',
                target,
                '-jsonl',
                '-silent',
                '-no-color',
                '-c',
                '8',
                '-rl',
                '30',
                '-bs',
                '25',
                '-timeout',
                '8',
                '-retries',
                '1',
                '-t',
                str(templates_path),
            ],
        )

    def _resolve_wordlist(self) -> tuple[str | None, str]:
        candidates = [
            Path('/opt/seclists/Discovery/Web-Content/common.txt'),
            Path('/usr/share/wordlists/dirb/common.txt'),
            Path('/usr/share/seclists/Discovery/Web-Content/common.txt'),
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate), ''
        return None, 'Wordlist no encontrada (esperada: /opt/seclists/Discovery/Web-Content/common.txt); se omite gobuster/ffuf sin abortar el scan.'

    def _resolve_nuclei_templates(self) -> Path | None:
        candidates = [Path(p) for p in self._nuclei_template_candidates()]
        for candidate in candidates:
            if candidate and candidate.exists() and candidate.is_dir() and any(candidate.glob('**/*.yaml')):
                return candidate
        return None

    def _nuclei_template_candidates(self) -> list[str]:
        env_raw = os.environ.get('NUCLEI_TEMPLATES', '').strip()
        candidates: list[str] = []
        if env_raw:
            candidates.append(env_raw)
        candidates.extend(
            [
                str(Path.home() / 'nuclei-templates'),
                '/root/nuclei-templates',
                '/usr/local/nuclei-templates',
                '/opt/nuclei-templates',
            ]
        )
        return candidates

    def _interpret_headers(self, headers: dict[str, Any]) -> list[dict[str, Any]]:
        lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        interpreted: list[dict[str, Any]] = []
        for header_name, rule in HEADER_INTERPRETATION_RULES.items():
            present = header_name in lowered and bool(lowered.get(header_name))
            ok = present if rule['ok_when_present'] else not present
            status = 'OK' if ok else 'WARNING'
            interpreted.append(
                {
                    'header': header_name,
                    'title': rule['title'],
                    'status': status,
                    'value': lowered.get(header_name, ''),
                    'message': rule['ok_description'] if ok else rule['warning_description'],
                }
            )
        unknown_headers = sorted(set(lowered.keys()) - set(HEADER_INTERPRETATION_RULES.keys()))
        for extra in unknown_headers[:10]:
            interpreted.append(
                {
                    'header': extra,
                    'title': 'Header informativo',
                    'status': 'INFO',
                    'value': lowered.get(extra, ''),
                    'message': 'Header observado sin regla específica de interpretación.',
                }
            )
        return interpreted

    def _missing_dependency_result(self, tool: str, reason: str):
        return ToolExecutionResult(
            tool=tool,
            command=tool,
            return_code=2,
            stdout='',
            stderr=reason,
            missing_binary=False,
        )

    def _serialize_module_result(self, result: ToolExecutionResult, *, required: bool = False) -> dict[str, Any]:
        if result.missing_binary:
            state = 'skipped'
        elif result.timed_out:
            state = 'failed'
        elif result.return_code == 0:
            state = 'ok'
        else:
            state = 'failed' if required else 'warning'
        return {
            **vars(result),
            'state': state,
            'required': required,
            'stdout_excerpt': self._summarize_output(result.stdout, 400),
            'stderr_excerpt': self._summarize_output(result.stderr, 400),
        }

    def _summarize_output(self, raw: str, limit: int = 220) -> str:
        text = ' '.join((raw or '').split())
        if len(text) <= limit:
            return text
        return f'{text[: limit - 3]}...'

    def _extract_whatweb_plugins(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        plugins = payload.get('plugins')
        if isinstance(plugins, dict):
            return plugins
        return {}

    def _extract_plugin_text(self, plugin_value: Any) -> str:
        if isinstance(plugin_value, str):
            return plugin_value
        if isinstance(plugin_value, list):
            return ', '.join(str(v) for v in plugin_value if v)
        if isinstance(plugin_value, dict):
            for key in ('string', 'version', 'os', 'module'):
                value = plugin_value.get(key)
                if isinstance(value, list):
                    return ', '.join(str(v) for v in value if v)
                if value:
                    return str(value)
            return ', '.join(f'{k}={v}' for k, v in plugin_value.items() if v)
        return str(plugin_value or '')

    def _group_interpreted_headers(self, interpreted_headers: list[dict[str, Any]]) -> dict[str, Any]:
        present = [item for item in interpreted_headers if item.get('status') == 'OK']
        absent = [
            item
            for item in interpreted_headers
            if item.get('status') == 'WARNING' and item.get('header') not in {'server', 'x-powered-by'}
        ]
        exposure = [
            item
            for item in interpreted_headers
            if item.get('status') == 'WARNING' and item.get('header') in {'server', 'x-powered-by'}
        ]
        informational = [item for item in interpreted_headers if item.get('status') == 'INFO']
        return {
            'present': present,
            'absent': absent,
            'exposure': exposure,
            'informational': informational,
            'summary': {
                'present': len(present),
                'absent': len(absent),
                'informational': len(informational) + len(exposure),
            },
        }

    def _dedupe_endpoints(self, target: str, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, Any]] = set()
        for endpoint in endpoints:
            path = str(endpoint.get('path') or '').strip() or '/'
            if not path.startswith('/'):
                path = f'/{path}'
            status = endpoint.get('status_code')
            key = (path, status)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(
                {
                    **endpoint,
                    'path': path,
                    'url': endpoint.get('url') or f'{target.rstrip("/")}{path}',
                }
            )
        return deduped

    def _dedupe_vulnerabilities(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for vuln in vulnerabilities:
            key = (
                str(vuln.get('type') or ''),
                str(vuln.get('name') or ''),
                str(vuln.get('matched_at') or ''),
                str(vuln.get('reference') or ''),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(vuln)
        return deduped

    def _build_whatweb_fingerprint(self, payload: dict[str, Any], target: str) -> dict[str, Any]:
        plugins = self._extract_whatweb_plugins(payload)
        technologies = sorted(plugins.keys()) if isinstance(plugins, dict) else []
        return {
            'target': payload.get('target') or target,
            'ip': payload.get('ip') or '',
            'http_status': payload.get('http_status') or payload.get('status') or '',
            'country': payload.get('country') or '',
            'server': self._extract_plugin_text(plugins.get('HTTPServer')) if isinstance(plugins, dict) else '',
            'x_powered_by': self._extract_plugin_text(plugins.get('X-Powered-By')) if isinstance(plugins, dict) else '',
            'plugins': plugins if isinstance(plugins, dict) else {},
            'technologies': technologies,
            'redirections': payload.get('redirection') or payload.get('redirects') or [],
        }

    def _build_basic_web_findings(self, *, endpoints: list[dict[str, Any]], headers_analysis: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for endpoint in endpoints[:15]:
            status = endpoint.get('status_code')
            if status in {200, 401, 403}:
                findings.append(
                    {
                        'title': 'Endpoint sensible descubierto',
                        'severity': 'low',
                        'evidence': f"{endpoint.get('path')} ({status})",
                    }
                )
        for header in headers_analysis.get('absent', [])[:4]:
            findings.append(
                {
                    'title': f"Header faltante: {header.get('header')}",
                    'severity': 'medium',
                    'evidence': header.get('message'),
                }
            )
        return findings
