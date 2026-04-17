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
    parse_katana_output,
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
WEB_SCAN_TYPES = {'web_basic', 'web_misconfig', 'web_full', 'web_wordpress', 'web_api', 'web_appsec', 'wordpress_scan'}

SENSITIVE_ENDPOINT_TOKENS = (
    'admin', 'login', 'signin', 'dashboard', 'auth', 'oauth', 'api', 'graphql', 'internal', 'debug', 'backup', 'config',
)

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

WEB_APPSEC_PRESETS = {
    'low': {'rate_limit': 2, 'concurrency': 1, 'max_depth': 2, 'max_endpoints': 120, 'module_timeout': 120},
    'medium': {'rate_limit': 4, 'concurrency': 2, 'max_depth': 3, 'max_endpoints': 320, 'module_timeout': 180},
    'high': {'rate_limit': 8, 'concurrency': 3, 'max_depth': 4, 'max_endpoints': 700, 'module_timeout': 300},
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
    def __init__(self, progress_callback=None) -> None:
        self.nmap_runner = NmapRunner()
        self.nmap_parser = NmapXmlParser()
        self.external_runner = ExternalToolRunner()
        self.progress_callback = progress_callback

    def execute(self, scan: ScanExecution) -> ScanPipelineResult:
        requested_scan_type = (scan.engine_metadata or {}).get('requested_scan_type') or 'nmap_discovery'
        if requested_scan_type in INFRA_SCAN_TYPES:
            return self._run_infra_pipeline(scan, requested_scan_type)
        if requested_scan_type in WEB_SCAN_TYPES:
            return self._run_web_pipeline(scan, requested_scan_type)
        return self._run_infra_pipeline(scan, 'nmap_discovery')

    def _notify_progress(self, stage: str, percent: int, message: str = '') -> None:
        if callable(self.progress_callback):
            self.progress_callback(stage, percent, message)

    def _run_infra_pipeline(self, scan: ScanExecution, scan_type: str) -> ScanPipelineResult:
        profile = NMAP_PROFILE_BY_SCAN_TYPE.get(scan_type, 'discovery')
        self._notify_progress('discovery', 15, 'Descubriendo servicios con Nmap')
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

        self._notify_progress('service_detection', 45, 'Procesando servicios detectados')
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
        self._notify_progress('version_detection', 65, 'Normalizando versiones y banners')

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
            'structured_results': {
                'category': 'infra',
                'target': scan.asset.value,
                'hosts': len(parsed_output.hosts),
                'services': scan.service_findings.count(),
                'tools': {'executed': ['nmap'], 'available': ['nmap'], 'skipped': [], 'failed': []},
                'warnings': [],
                'partial_result': timed_out or bool(parse_metadata.get('recovered_partial_xml')),
            },
        }
        self._notify_progress('enrichment', 82, 'Consolidando evidencia de infraestructura')
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
        endpoints_by_source: dict[str, int] = {'gobuster': 0, 'ffuf': 0}
        interpreted_headers: list[dict[str, Any]] = []
        cms = ''
        fingerprint_detected = False
        whatweb_signals: list[str] = []
        appsec_requested = self._resolve_web_appsec_configuration(scan, scan_type)
        appsec_controls = appsec_requested.get('controls', {})
        web_scan_controls = self._resolve_web_scan_controls(scan=scan, scan_type=scan_type, appsec_controls=appsec_controls)

        self._notify_progress('http_probe', 15, 'Validando conectividad HTTP/S')
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
            'katana': self.external_runner.is_available('katana'),
            'wpscan': self.external_runner.is_available('wpscan'),
            'httpx': self.external_runner.is_available('httpx'),
            'sqlmap': self.external_runner.is_available('sqlmap'),
            'dalfox': self.external_runner.is_available('dalfox'),
            'zap-baseline.py': self.external_runner.is_available('zap-baseline.py'),
            'dirsearch': self.external_runner.is_available('dirsearch'),
        }
        dependency_checks = {
            'whatweb': {'available': tool_presence['whatweb'], 'required': True},
            'nuclei': {'available': tool_presence['nuclei'], 'required': scan_type in {'web_full', 'web_misconfig', 'web_appsec'}},
            'gobuster': {'available': tool_presence['gobuster'], 'required': False},
            'ffuf': {'available': tool_presence['ffuf'], 'required': False},
            'katana': {'available': tool_presence['katana'], 'required': scan_type in {'web_full', 'web_appsec'}},
            'gobuster_or_ffuf': {
                'available': tool_presence['gobuster'] or tool_presence['ffuf'],
                'required': True,
            },
            'nikto': {'available': tool_presence['nikto'], 'required': scan_type in {'web_misconfig'}},
            'wpscan': {'available': tool_presence['wpscan'], 'required': scan_type in {'web_wordpress', 'wordpress_scan'}},
            'httpx': {'available': tool_presence['httpx'], 'required': scan_type == 'web_appsec'},
            'sqlmap': {'available': tool_presence['sqlmap'], 'required': scan_type == 'web_appsec' and 'sqli' in appsec_requested.get('modules', [])},
            'dalfox': {'available': tool_presence['dalfox'], 'required': scan_type == 'web_appsec' and 'xss' in appsec_requested.get('modules', [])},
            'zap-baseline.py': {'available': tool_presence['zap-baseline.py'], 'required': scan_type == 'web_appsec' and 'misconfig' in appsec_requested.get('modules', [])},
            'dirsearch': {'available': tool_presence['dirsearch'], 'required': False},
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
                if tool_name == 'nuclei' and 'failed to create new os thread' in (result.stderr or '').lower():
                    details = (
                        'Nuclei alcanzó límite de hilos/procesos del contenedor. '
                        'Se aplicaron límites defensivos; revisar recursos del worker o reducir preset.'
                    )
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
        self._notify_progress('fingerprint', 35, 'Ejecutando fingerprint de tecnologías')
        whatweb = self.run_whatweb(target)
        if _record_module('whatweb', whatweb, required=True):
            ww_payload = parse_whatweb_json(whatweb.stdout)
            plugins = self._extract_whatweb_plugins(ww_payload)
            fingerprint = self._build_whatweb_fingerprint(ww_payload, target, headers)
            whatweb_signals = self._extract_whatweb_signals(plugins)
            if isinstance(plugins, dict):
                technologies.update(self._normalize_technology_names(plugins.keys()))
                technologies.update(self._normalize_technology_names(whatweb_signals))
                fingerprint_detected = bool(plugins or whatweb_signals)
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
        self._notify_progress('endpoint_discovery', 55, 'Descubriendo endpoints y superficies expuestas')
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
                    minimum_expected = int(os.environ.get('WEB_ENUM_MIN_ENDPOINTS', '2'))
                    if (
                        len(endpoints) < minimum_expected
                        and tool_presence.get(fallback_enum_tool)
                        and fallback_enum_tool != enum_tool
                    ):
                        warnings.append(
                            f'{enum_tool} devolvió pocos endpoints ({len(endpoints)}); se ejecuta fallback con {fallback_enum_tool}.'
                        )
                        fallback_result = (
                            self.run_ffuf(target, wordlist)
                            if fallback_enum_tool == 'ffuf'
                            else self.run_gobuster(target, wordlist)
                        )
                        if _record_module(fallback_enum_tool, fallback_result):
                            fallback_endpoints = (
                                parse_ffuf_output(fallback_result.stdout)
                                if fallback_enum_tool == 'ffuf'
                                else parse_gobuster_json(fallback_result.stdout)
                            )
                            endpoints.extend(fallback_endpoints)
                    endpoints = self._enrich_endpoint_priority(endpoints)
                    endpoints = self._dedupe_endpoints(target, endpoints)
                    endpoints_by_source = self._count_endpoints_by_source(endpoints)
                    endpoints_by_status = self._count_endpoints_by_status(endpoints)
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
                endpoints_by_status = {}

        if scan_type in {'web_full', 'web_appsec'}:
            katana_res = self.run_katana(target, controls=web_scan_controls)
            if _record_module('katana', katana_res, required=scan_type == 'web_appsec'):
                katana_endpoints = parse_katana_output(katana_res.stdout)
                if katana_endpoints:
                    endpoints.extend(katana_endpoints)
                    endpoints = self._enrich_endpoint_priority(endpoints)
                    endpoints = self._dedupe_endpoints(target, endpoints)
                    endpoints_by_source = self._count_endpoints_by_source(endpoints)
                    endpoints_by_status = self._count_endpoints_by_status(endpoints)
                    RawEvidence.objects.create(
                        organization=scan.organization,
                        scan_execution=scan,
                        source='katana',
                        host=target,
                        payload={'endpoints': katana_endpoints},
                        raw_output=katana_res.stdout,
                        metadata={
                            'stderr': katana_res.stderr,
                            'stdout_excerpt': self._summarize_output(katana_res.stdout, 400),
                            'command': katana_res.command,
                            'scan_type': scan_type,
                        },
                    )

        max_endpoints = int(web_scan_controls.get('max_endpoints') or WEB_APPSEC_PRESETS['medium']['max_endpoints'])
        if len(endpoints) > max_endpoints:
            endpoints = endpoints[:max_endpoints]
            warnings.append(
                f'Se limitaron endpoints a {max_endpoints} por configuración operativa ({scan_type}).'
            )

        interpreted_headers = self._interpret_headers(headers)

        # 3) Vulnerabilidades
        self._notify_progress('vulnerability_checks', 76, 'Ejecutando validaciones de vulnerabilidades')
        run_nuclei = scan_type in {'web_basic', 'web_full', 'web_appsec', 'web_misconfig', 'web_api'}
        nuclei_required = scan_type in {'web_full', 'web_misconfig'}
        if run_nuclei:
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
                nuclei_res = self.run_nuclei(target, nuclei_templates, scan_type=scan_type, controls=web_scan_controls)
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
                            'templates_path': str(nuclei_templates) if nuclei_templates else '',
                        },
                    )

        if scan_type in {'web_basic', 'web_full', 'web_misconfig', 'web_appsec'}:
            nikto_timeout = int(web_scan_controls.get('module_timeout') or WEB_APPSEC_PRESETS['medium']['module_timeout'])
            nikto_res = self.external_runner.run('nikto', ['-h', target, '-Format', 'txt'], timeout=nikto_timeout)
            if _record_module('nikto', nikto_res, required=scan_type == 'web_misconfig'):
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
        if scan_type == 'web_appsec':
            appsec_vulnerabilities, appsec_observations, appsec_sensitive_endpoints = self._run_web_appsec_modules(
                target=target,
                endpoints=endpoints,
                scan=scan,
                appsec_configuration=appsec_requested,
                controls=web_scan_controls,
                tools_presence=tool_presence,
                record_module=_record_module,
                warnings=warnings,
                tools_skipped=tools_skipped,
            )
            vulnerabilities.extend(appsec_vulnerabilities)
        else:
            appsec_observations = {}
            appsec_sensitive_endpoints = []
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
        vulnerabilities_by_severity = self._count_vulnerabilities_by_severity(vulnerabilities)
        headers_analysis = self._group_interpreted_headers(interpreted_headers)
        web_basic_findings = self._build_basic_web_findings(endpoints=endpoints, headers_analysis=headers_analysis)
        redirects = self._extract_redirects(fingerprint, endpoints)
        web_enterprise_findings = self._build_enterprise_web_findings(
            target=target,
            headers=headers,
            interpreted_headers=interpreted_headers,
            endpoints=endpoints,
            technologies=technologies,
            redirects=redirects,
            whatweb_signals=whatweb_signals,
            cms=cms,
        )
        web_findings_all = self._merge_web_findings(web_enterprise_findings, web_basic_findings)
        self._notify_progress('reporting', 86, 'Consolidando hallazgos web')

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
                confidence = (vuln.get('confidence') or Finding.Confidence.MEDIUM).lower()
                if confidence not in dict(Finding.Confidence.choices):
                    confidence = Finding.Confidence.MEDIUM
                endpoint = vuln.get('matched_at') or vuln.get('host') or target
                parameter = vuln.get('parameter') or ''
                owasp_category = vuln.get('owasp_category') or ''
                cwe = vuln.get('cwe') or ''
                Finding.objects.get_or_create(
                    organization=scan.organization,
                    scan_execution=scan,
                    asset=scan.asset,
                    title=vuln.get('name') or 'Web vulnerability',
                    defaults={
                        'description': (
                            f"{vuln.get('description', '')}\n"
                            f"Endpoint: {endpoint}\n"
                            f"Parámetro: {parameter or 'n/a'}\n"
                            f"Categoría OWASP/CWE: {owasp_category or cwe or 'n/a'}"
                        ).strip(),
                        'remediation': vuln.get('remediation') or 'Validar el hallazgo y aplicar actualización/configuración recomendada.',
                        'reference': vuln.get('reference', ''),
                        'severity': sev,
                        'confidence': confidence,
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

            for web_finding in web_enterprise_findings:
                sev = str(web_finding.get('severity') or Finding.Severity.LOW).lower()
                if sev not in dict(Finding.Severity.choices):
                    sev = Finding.Severity.LOW
                Finding.objects.get_or_create(
                    organization=scan.organization,
                    scan_execution=scan,
                    asset=scan.asset,
                    title=web_finding.get('title') or 'Web hardening finding',
                    defaults={
                        'description': web_finding.get('description', ''),
                        'remediation': web_finding.get('remediation', 'Aplicar hardening web según mejores prácticas.'),
                        'reference': ', '.join(web_finding.get('references') or [])[:500],
                        'severity': sev,
                        'confidence': Finding.Confidence.MEDIUM,
                        'status': Finding.Status.OPEN,
                    },
                )

        endpoints_by_status = self._count_endpoints_by_status(endpoints)
        module_status = self._build_module_status(modules)
        web_kpis = self._build_web_kpis(
            technologies=technologies,
            endpoints=endpoints,
            vulnerabilities=vulnerabilities,
            headers_analysis=headers_analysis,
            web_basic_findings=web_findings_all,
            redirects=redirects,
            module_status=module_status,
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
            'vulnerabilities_by_severity': vulnerabilities_by_severity,
            'endpoints_by_source': endpoints_by_source,
            'interpreted_headers_count': len(interpreted_headers),
            'cms': cms,
            'target': target,
            'aggressiveness': appsec_requested.get('aggressiveness'),
            'modules_selected': appsec_requested.get('modules', []),
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
        if not redirections:
            redirections = redirects
        executive_summary = self._build_web_executive_summary(
            target=target,
            http_status=http_status,
            technologies=technologies,
            endpoints=endpoints,
            vulnerabilities=vulnerabilities,
            warnings=warnings,
            cms=cms,
            redirects=redirections,
        )
        metadata = {
            'pipeline': 'web',
            'modules': modules,
            'structured_results': {
                'category': 'web',
                'target': target,
                'target_url': target,
                'http_status': http_status,
                'redirects': redirections,
                'http_probe': probe_result,
                'scan_type': scan_type,
                'technologies': sorted(technologies),
                'endpoints': endpoints,
                'web_findings_basic': web_basic_findings,
                'web_findings': web_findings_all,
                'web_findings_enterprise': web_enterprise_findings,
                'web_kpis': web_kpis,
                'vulnerabilities': vulnerabilities,
                'headers': headers,
                'interpreted_headers': interpreted_headers,
                'cms': cms,
                'fingerprint': fingerprint,
                'tools': tools_map,
                'module_status': module_status,
                'tools_available': tools_available,
                'tools_executed': tools_executed,
                'tools_failed': tools_failed,
                'tools_skipped': tools_skipped,
                'dependency_checks': dependency_checks,
                'warnings': warnings,
                'partial_result': bool(tools_skipped or warnings),
                'fingerprint_detected': fingerprint_detected,
                'headers_analysis': headers_analysis,
                'vulnerabilities_by_severity': vulnerabilities_by_severity,
                'endpoints_by_source': endpoints_by_source,
                'endpoints_by_status': endpoints_by_status,
                'whatweb_signals': whatweb_signals,
                'executive_summary': executive_summary,
                'appsec': appsec_observations if scan_type == 'web_appsec' else {},
                'sensitive_endpoints': appsec_sensitive_endpoints if scan_type == 'web_appsec' else [],
                'aggressiveness': appsec_requested.get('aggressiveness'),
                'modules_selected': appsec_requested.get('modules', []),
                'scan_controls': web_scan_controls,
                'scan_preset': web_scan_controls.get('preset', appsec_requested.get('aggressiveness', 'medium')),
            },
        }
        command_executed = '; '.join(
            module['command'] for module in modules.values() if isinstance(module, dict) and module.get('command')
        )
        return ScanPipelineResult(summary=summary, command_executed=command_executed, engine_metadata=metadata)

    def _resolve_web_appsec_configuration(self, scan: ScanExecution, scan_type: str) -> dict[str, Any]:
        defaults = {'aggressiveness': 'medium', 'modules': [], 'controls': WEB_APPSEC_PRESETS['medium'].copy()}
        if scan_type != 'web_appsec':
            return defaults
        raw = (scan.engine_metadata or {}).get('web_appsec') or {}
        aggressiveness = str(raw.get('aggressiveness') or 'medium').lower()
        if aggressiveness not in WEB_APPSEC_PRESETS:
            aggressiveness = 'medium'
        modules = raw.get('modules') or ['xss', 'sqli', 'misconfig', 'csrf', 'idor', 'auth', 'upload', 'ssrf', 'endpoint_discovery']
        modules = [str(module).strip().lower() for module in modules if str(module).strip()]
        controls = {**WEB_APPSEC_PRESETS[aggressiveness], **(raw.get('controls') or {})}
        controls['exclude_paths'] = [str(v).strip() for v in controls.get('exclude_paths', []) if str(v).strip()]
        controls['allowlist_domains'] = [str(v).strip().lower() for v in controls.get('allowlist_domains', []) if str(v).strip()]
        return {'aggressiveness': aggressiveness, 'modules': modules, 'controls': controls}

    def _resolve_web_scan_controls(self, *, scan: ScanExecution, scan_type: str, appsec_controls: dict[str, Any]) -> dict[str, Any]:
        metadata = (scan.engine_metadata or {}).get('web_scan') or {}
        defaults = WEB_APPSEC_PRESETS['medium'].copy()
        raw_controls = metadata.get('controls') if isinstance(metadata, dict) else {}
        controls = {**defaults, **(raw_controls or {})}
        if scan_type == 'web_appsec':
            controls = {**controls, **(appsec_controls or {})}
        controls['preset'] = str(metadata.get('preset') or controls.get('preset') or 'medium').lower()
        controls['rate_limit'] = max(1, int(controls.get('rate_limit') or defaults['rate_limit']))
        controls['concurrency'] = max(1, int(controls.get('concurrency') or defaults['concurrency']))
        controls['max_depth'] = max(1, int(controls.get('max_depth') or defaults['max_depth']))
        controls['max_endpoints'] = max(10, int(controls.get('max_endpoints') or defaults['max_endpoints']))
        controls['module_timeout'] = max(30, int(controls.get('module_timeout') or defaults['module_timeout']))
        return controls

    def _run_web_appsec_modules(
        self,
        *,
        target: str,
        endpoints: list[dict[str, Any]],
        scan: ScanExecution,
        appsec_configuration: dict[str, Any],
        controls: dict[str, Any],
        tools_presence: dict[str, bool],
        record_module: Any,
        warnings: list[str],
        tools_skipped: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
        modules = set(appsec_configuration.get('modules') or [])
        module_timeout = int(controls.get('module_timeout') or WEB_APPSEC_PRESETS[appsec_configuration.get('aggressiveness', 'medium')]['module_timeout'])
        prioritized_endpoints = [row for row in endpoints if row.get('priority') in {'high', 'medium'}][: min(20, len(endpoints))]
        suspicious_params = self._extract_suspicious_parameters(prioritized_endpoints)
        forms_detected = [row for row in prioritized_endpoints if any(token in str(row.get('path', '')).lower() for token in ('login', 'signup', 'register', 'reset'))]
        uploads_detected = [row for row in prioritized_endpoints if 'upload' in str(row.get('path', '')).lower()]
        ssrf_patterns = [row for row in prioritized_endpoints if any(token in str(row.get('path', '')).lower() for token in ('url=', 'redirect', 'callback', 'proxy', 'fetch'))]
        auth_surface = [row for row in prioritized_endpoints if any(token in str(row.get('path', '')).lower() for token in ('auth', 'login', 'token', 'session'))]
        idor_surface = [row for row in prioritized_endpoints if any(token in str(row.get('path', '')).lower() for token in ('id=', '/users/', '/accounts/', '/orders/'))]

        vulns: list[dict[str, Any]] = []
        if 'xss' in modules and tools_presence.get('dalfox') and prioritized_endpoints:
            dalfox_target = prioritized_endpoints[0].get('url') or target
            dalfox = self.external_runner.run('dalfox', ['url', dalfox_target, '--silence'], timeout=module_timeout)
            if record_module('dalfox', dalfox, required=False):
                if dalfox.stdout:
                    vulns.append({'name': 'Potential XSS signal (dalfox)', 'severity': 'high', 'description': 'Dalfox reportó una señal potencial de XSS.', 'matched_at': dalfox_target, 'reference': 'https://owasp.org/www-community/attacks/xss/', 'type': 'dalfox', 'owasp_category': 'A03:2021-Injection', 'confidence': 'medium'})
        elif 'xss' in modules and not tools_presence.get('dalfox'):
            warnings.append('Módulo XSS habilitado pero dalfox no está disponible.')
            tools_skipped.append({'tool': 'dalfox', 'reason': 'missing_binary', 'required': False})

        if 'sqli' in modules and tools_presence.get('sqlmap') and suspicious_params:
            sqlmap_target = suspicious_params[0].get('url') or target
            sqlmap = self.external_runner.run('sqlmap', ['-u', sqlmap_target, '--batch', '--risk=1', '--level=1'], timeout=module_timeout)
            if record_module('sqlmap', sqlmap, required=False):
                if 'is vulnerable' in (sqlmap.stdout or '').lower():
                    vulns.append({'name': 'Potential SQL injection signal (sqlmap)', 'severity': 'high', 'description': 'sqlmap detectó un posible vector SQLi.', 'matched_at': sqlmap_target, 'reference': 'https://owasp.org/www-community/attacks/SQL_Injection', 'type': 'sqlmap', 'owasp_category': 'A03:2021-Injection', 'confidence': 'medium'})
        elif 'sqli' in modules and not tools_presence.get('sqlmap'):
            warnings.append('Módulo SQLi habilitado pero sqlmap no está disponible.')
            tools_skipped.append({'tool': 'sqlmap', 'reason': 'missing_binary', 'required': False})

        if 'misconfig' in modules and tools_presence.get('zap-baseline.py'):
            zap = self.external_runner.run('zap-baseline.py', ['-t', target, '-m', '1'], timeout=module_timeout)
            record_module('zap-baseline.py', zap, required=False)
        elif 'misconfig' in modules and not tools_presence.get('zap-baseline.py'):
            warnings.append(
                'OWASP ZAP baseline no está disponible en esta imagen ligera del worker; '
                'se mantiene fallback con Nikto + Nuclei misconfig.'
            )
            tools_skipped.append({'tool': 'zap-baseline.py', 'reason': 'missing_binary', 'required': False})

        findings_by_family = {
            'xss': [v for v in vulns if v.get('type') == 'dalfox'],
            'sqli': [v for v in vulns if v.get('type') == 'sqlmap'],
            'csrf_review': self._surface_rows(forms_detected, title='CSRF review required', severity='medium', category='A01:2021-Broken Access Control'),
            'idor_surface': self._surface_rows(idor_surface, title='IDOR/Broken Access Control surface', severity='medium', category='A01:2021-Broken Access Control'),
            'auth_surface': self._surface_rows(auth_surface, title='Authentication attack surface', severity='medium', category='A07:2021-Identification and Authentication Failures'),
            'upload_surface': self._surface_rows(uploads_detected, title='File upload surface', severity='medium', category='A05:2021-Security Misconfiguration'),
            'ssrf_surface': self._surface_rows(ssrf_patterns, title='Potential SSRF surface', severity='medium', category='A10:2021-Server-Side Request Forgery'),
        }
        sensitive_endpoints = [row for row in prioritized_endpoints if row.get('priority') == 'high']
        appsec = {
            'findings_by_family': findings_by_family,
            'suspicious_parameters': suspicious_params,
            'forms_detected': forms_detected,
            'uploads_detected': uploads_detected,
            'ssrf_patterns': ssrf_patterns,
            'auth_surface': auth_surface,
            'idor_surface': idor_surface,
            'owasp_categories': self._count_owasp_categories(vulns),
        }
        return vulns, appsec, sensitive_endpoints

    def _surface_rows(self, rows: list[dict[str, Any]], *, title: str, severity: str, category: str) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for row in rows[:50]:
            normalized.append(
                {
                    'name': title,
                    'severity': severity,
                    'description': f'Revisar superficie expuesta en {row.get("path") or row.get("url")}',
                    'matched_at': row.get('url') or row.get('path') or '',
                    'reference': '',
                    'type': 'surface',
                    'owasp_category': category,
                    'confidence': 'low',
                }
            )
        return normalized

    def _extract_suspicious_parameters(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        suspicious: list[dict[str, Any]] = []
        for endpoint in endpoints:
            endpoint_url = str(endpoint.get('url') or '')
            if '?' not in endpoint_url:
                continue
            for parameter in endpoint_url.split('?', 1)[-1].split('&'):
                key = parameter.split('=', 1)[0].strip().lower()
                if key in {'id', 'user', 'account', 'redirect', 'url', 'next', 'return', 'callback', 'file'}:
                    suspicious.append({'url': endpoint_url, 'parameter': key})
        return suspicious[:100]

    def _count_owasp_categories(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
        totals: dict[str, int] = {}
        for vuln in vulnerabilities:
            category = str(vuln.get('owasp_category') or 'Unclassified')
            totals[category] = totals.get(category, 0) + 1
        return totals

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
                '-r',
                '--status-codes',
                '200,204,301,302,307,308,401,403',
                '--status-codes-blacklist',
                '',
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

    def run_katana(self, target: str, *, controls: dict[str, Any] | None = None):
        controls = controls or {}
        depth = str(controls.get('max_depth') or os.environ.get('KATANA_DEPTH', '2'))
        concurrency = str(controls.get('concurrency') or os.environ.get('KATANA_CONCURRENCY', '2'))
        rate_limit = str(controls.get('rate_limit') or os.environ.get('KATANA_RATE_LIMIT', '4'))
        return self.external_runner.run(
            'katana',
            [
                '-u',
                target,
                '-jsonl',
                '-silent',
                '-d',
                depth,
                '-c',
                concurrency,
                '-rl',
                rate_limit,
                '-timeout',
                os.environ.get('KATANA_TIMEOUT', '8'),
            ],
            timeout=int(controls.get('module_timeout') or os.environ.get('KATANA_TOOL_TIMEOUT', '120')),
        )

    def run_nuclei(self, target: str, templates_path: Path, *, scan_type: str = 'web_basic', controls: dict[str, Any] | None = None):
        controls = controls or {}
        profile_tags = {
            'web_basic': 'misconfig,exposure',
            'web_misconfig': 'misconfig,default-logins,exposure,ssl',
            'web_full': 'misconfig,exposure,cves',
            'web_appsec': 'misconfig,xss,sqli',
            'web_api': 'api,misconfig,exposure',
        }
        rate_limit = str(min(6, max(1, int(controls.get('rate_limit') or os.environ.get('NUCLEI_RATE_LIMIT', '2')))))
        concurrency = str(min(2, max(1, int(controls.get('concurrency') or os.environ.get('NUCLEI_CONCURRENCY', '1')))))
        timeout = str(min(10, max(3, int(os.environ.get('NUCLEI_TIMEOUT', '6')))))
        return self.external_runner.run(
            'nuclei',
            [
                '-u',
                target,
                '-jsonl',
                '-silent',
                '-no-color',
                '-c',
                concurrency,
                '-rl',
                rate_limit,
                '-bs',
                '1',
                '-timeout',
                timeout,
                '-retries',
                os.environ.get('NUCLEI_RETRIES', '0'),
                '-max-host-error',
                '1',
                '-tl',
                os.environ.get('NUCLEI_TEMPLATE_THREADS', '1'),
                '-headless-bulk-size',
                os.environ.get('NUCLEI_HEADLESS_BULK_SIZE', '1'),
                '-no-interactsh',
                '-project',
                '-disable-update-check',
                '-tags',
                os.environ.get('NUCLEI_PROFILE_TAGS', profile_tags.get(scan_type, 'misconfig,exposure')),
                '-t',
                str(templates_path),
            ],
            timeout=int(controls.get('module_timeout') or os.environ.get('NUCLEI_TOOL_TIMEOUT', '180')),
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
        seen: set[tuple[str, Any, str]] = set()
        for endpoint in endpoints:
            path = str(endpoint.get('path') or '').strip() or '/'
            if not path.startswith('/'):
                path = f'/{path}'
            status = endpoint.get('status_code')
            source = str(endpoint.get('source') or 'unknown')
            key = (path, status, source)
            if key in seen:
                continue
            seen.add(key)
            redirect = endpoint.get('redirect') or ''
            priority = self._endpoint_priority(path, status)
            deduped.append(
                {
                    **endpoint,
                    'path': path,
                    'url': endpoint.get('url') or f'{target.rstrip("/")}{path}',
                    'redirect': redirect,
                    'priority': priority,
                }
            )
        return sorted(deduped, key=lambda row: (-self._priority_rank(row.get('priority')), row.get('path', '/')))

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

    def _build_whatweb_fingerprint(self, payload: dict[str, Any], target: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        plugins = self._extract_whatweb_plugins(payload)
        technologies = sorted(plugins.keys()) if isinstance(plugins, dict) else []
        response_headers: dict[str, Any] = {}
        uncommon_headers: dict[str, Any] = {}
        for name, value in (headers or {}).items():
            key = str(name).strip().lower()
            if key in {'server', 'x-powered-by', 'content-type', 'strict-transport-security', 'x-frame-options'}:
                response_headers[key] = value
            elif key.startswith('x-') or key in {'content-security-policy', 'permissions-policy', 'referrer-policy'}:
                uncommon_headers[key] = value
        return {
            'target': payload.get('target') or target,
            'ip': payload.get('ip') or '',
            'http_status': payload.get('http_status') or payload.get('status') or '',
            'country': payload.get('country') or '',
            'server': self._extract_plugin_text(plugins.get('HTTPServer')) if isinstance(plugins, dict) else '',
            'x_powered_by': self._extract_plugin_text(plugins.get('X-Powered-By')) if isinstance(plugins, dict) else '',
            'plugins': plugins if isinstance(plugins, dict) else {},
            'fingerprint_plugins': plugins if isinstance(plugins, dict) else {},
            'technologies': technologies,
            'response_headers': response_headers,
            'uncommon_headers': uncommon_headers,
            'redirections': payload.get('redirection') or payload.get('redirects') or [],
        }

    def _count_endpoints_by_source(self, endpoints: list[dict[str, Any]]) -> dict[str, int]:
        totals: dict[str, int] = {'gobuster': 0, 'ffuf': 0, 'katana': 0}
        for endpoint in endpoints:
            source = str(endpoint.get('source') or 'unknown').lower()
            totals[source] = totals.get(source, 0) + 1
        return totals

    def _count_endpoints_by_status(self, endpoints: list[dict[str, Any]]) -> dict[str, int]:
        totals: dict[str, int] = {}
        for endpoint in endpoints:
            status = endpoint.get('status_code')
            key = str(status) if status is not None else 'unknown'
            totals[key] = totals.get(key, 0) + 1
        return dict(sorted(totals.items(), key=lambda row: row[0]))

    def _count_vulnerabilities_by_severity(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
        totals = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            sev = str(vuln.get('severity') or 'medium').lower()
            if sev not in totals:
                sev = 'info'
            totals[sev] += 1
        return totals

    def _endpoint_priority(self, path: str, status_code: Any) -> str:
        path_lc = str(path).lower()
        sensitive_tokens = ('admin', 'login', 'dashboard', 'api', 'config', 'backup', 'internal', 'debug', 'wp-admin')
        sensitive = any(token in path_lc for token in sensitive_tokens)
        if sensitive and status_code in {200, 401, 403}:
            return 'high'
        if status_code in {301, 302, 307, 308}:
            return 'medium'
        return 'low'

    def _priority_rank(self, priority: Any) -> int:
        ranks = {'high': 3, 'medium': 2, 'low': 1}
        return ranks.get(str(priority).lower(), 0)

    def _enrich_endpoint_priority(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        enriched = []
        for endpoint in endpoints:
            path = str(endpoint.get('path') or '/')
            status_code = endpoint.get('status_code')
            enriched.append({**endpoint, 'priority': self._endpoint_priority(path, status_code)})
        return enriched

    def _normalize_technology_names(self, raw_items: Any) -> set[str]:
        if not raw_items:
            return set()
        normalized: set[str] = set()
        alias_map = {
            'httpserver': 'HTTP Server',
            'x-powered-by': 'X-Powered-By',
            'jquery': 'jQuery',
            'bootstrap': 'Bootstrap',
            'nginx': 'Nginx',
            'apache': 'Apache HTTP Server',
            'php': 'PHP',
        }
        for item in raw_items:
            text = str(item or '').strip()
            if not text:
                continue
            canonical = alias_map.get(text.lower(), text)
            normalized.add(canonical)
        return normalized

    def _extract_whatweb_signals(self, plugins: dict[str, Any]) -> list[str]:
        signals: list[str] = []
        if not isinstance(plugins, dict):
            return signals
        for plugin_name, plugin_value in plugins.items():
            signals.append(str(plugin_name))
            extracted = self._extract_plugin_text(plugin_value)
            for token in re.split(r'[,/;| ]+', extracted):
                token = token.strip()
                if len(token) < 3:
                    continue
                if re.match(r'^\d+(\.\d+)+$', token):
                    continue
                signals.append(token)
        return signals

    def _extract_redirects(self, fingerprint: dict[str, Any], endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        redirects: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        raw_redirects = fingerprint.get('redirections') or []
        if isinstance(raw_redirects, list):
            for item in raw_redirects:
                if isinstance(item, dict):
                    src = str(item.get('from') or item.get('request') or '')
                    dst = str(item.get('to') or item.get('location') or item.get('url') or '')
                else:
                    src = ''
                    dst = str(item)
                key = (src, dst)
                if dst and key not in seen:
                    seen.add(key)
                    redirects.append({'from': src, 'to': dst, 'source': 'whatweb'})
        for endpoint in endpoints:
            status_code = endpoint.get('status_code')
            location = str(endpoint.get('redirect') or '')
            if status_code in {301, 302, 307, 308} and location:
                key = (str(endpoint.get('path') or ''), location)
                if key in seen:
                    continue
                seen.add(key)
                redirects.append(
                    {
                        'from': endpoint.get('path') or '',
                        'to': location,
                        'source': endpoint.get('source') or 'enumeration',
                    }
                )
        return redirects

    def _build_module_status(self, modules: dict[str, Any]) -> dict[str, int]:
        totals = {'ok': 0, 'failed': 0, 'warning': 0, 'skipped': 0}
        for module_data in modules.values():
            if not isinstance(module_data, dict):
                continue
            state = str(module_data.get('state') or '').lower()
            if state in totals:
                totals[state] += 1
        return totals

    def _build_web_executive_summary(
        self,
        *,
        target: str,
        http_status: Any,
        technologies: set[str],
        endpoints: list[dict[str, Any]],
        vulnerabilities: list[dict[str, Any]],
        warnings: list[str],
        cms: str,
        redirects: list[dict[str, Any]],
    ) -> str:
        return (
            f"Objetivo {target} respondió con HTTP {http_status or 'N/A'}. "
            f"Se detectaron {len(technologies)} tecnologías, {len(endpoints)} endpoints, "
            f"{len(redirects)} redirecciones y {len(vulnerabilities)} vulnerabilidades. "
            f"CMS: {cms or 'no detectado'}. Warnings técnicos: {len(warnings)}."
        )

    def _build_web_kpis(
        self,
        *,
        technologies: set[str],
        endpoints: list[dict[str, Any]],
        vulnerabilities: list[dict[str, Any]],
        headers_analysis: dict[str, Any],
        web_basic_findings: list[dict[str, Any]],
        redirects: list[dict[str, Any]],
        module_status: dict[str, int],
    ) -> dict[str, Any]:
        vulnerabilities_by_severity = self._count_vulnerabilities_by_severity(vulnerabilities)
        controls_present = len(headers_analysis.get('present') or [])
        controls_absent = len(headers_analysis.get('absent') or [])
        exposure_observed = len(headers_analysis.get('exposure') or [])
        total_controls = max(controls_present + controls_absent + exposure_observed, 1)
        score = int((controls_present / total_controls) * 100)
        return {
            'technologies_detected': len(technologies),
            'endpoints_discovered': len(endpoints),
            'vulnerabilities_detected': len(vulnerabilities),
            'web_basic_findings': len(web_basic_findings),
            'controls_present': controls_present,
            'controls_absent': controls_absent,
            'exposure_observed': exposure_observed,
            'redirects_detected': len(redirects),
            'severity_aggregate': vulnerabilities_by_severity,
            'score': score,
            'module_status': module_status,
            'kpi_blocks': [
                {
                    'key': 'controls_present',
                    'label': 'Controles presentes',
                    'value': controls_present,
                    'context': 'Headers de hardening detectados y activos.',
                },
                {
                    'key': 'controls_absent',
                    'label': 'Controles ausentes',
                    'value': controls_absent,
                    'context': 'Controles esperados sin evidencia en la respuesta.',
                },
                {
                    'key': 'exposure_observed',
                    'label': 'Exposición tecnológica',
                    'value': exposure_observed,
                    'context': 'Headers/banners que facilitan fingerprinting.',
                },
                {
                    'key': 'endpoints_discovered',
                    'label': 'Endpoints descubiertos',
                    'value': len(endpoints),
                    'context': 'Superficie observable vía enumeración/crawling.',
                },
                {
                    'key': 'technologies_detected',
                    'label': 'Tecnologías detectadas',
                    'value': len(technologies),
                    'context': 'Stack deducido por fingerprint y señales de respuesta.',
                },
                {
                    'key': 'web_basic_findings',
                    'label': 'Hallazgos web',
                    'value': len(web_basic_findings),
                    'context': 'Misconfiguraciones y superficies de riesgo detectadas.',
                },
            ],
        }

    def _build_basic_web_findings(self, *, endpoints: list[dict[str, Any]], headers_analysis: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for endpoint in endpoints[:15]:
            status = endpoint.get('status_code')
            if status in {200, 401, 403}:
                key = ('endpoint', str(endpoint.get('path')))
                if key in seen:
                    continue
                seen.add(key)
                findings.append({'title': 'Endpoint sensible descubierto', 'severity': 'low', 'evidence': f"{endpoint.get('path')} ({status})"})
        for header in headers_analysis.get('absent', [])[:4]:
            header_name = str(header.get('header') or '')
            key = ('header_absent', header_name)
            if key in seen:
                continue
            seen.add(key)
            findings.append({'title': f"Header faltante: {header_name}", 'severity': 'medium', 'evidence': header.get('message')})
        return findings

    def _merge_web_findings(self, primary: list[dict[str, Any]], fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for item in [*(primary or []), *(fallback or [])]:
            title = str(item.get('title') or '').strip()
            evidence = str(item.get('evidence') or '').strip()
            key = (title.lower(), evidence.lower())
            if not title or key in seen:
                continue
            seen.add(key)
            merged.append(item)
        return merged

    def _build_enterprise_web_findings(
        self,
        *,
        target: str,
        headers: dict[str, str],
        interpreted_headers: list[dict[str, Any]],
        endpoints: list[dict[str, Any]],
        technologies: set[str],
        redirects: list[dict[str, Any]],
        whatweb_signals: list[str],
        cms: str,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        headers_lc = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        header_lookup = {row.get('header'): row for row in interpreted_headers if isinstance(row, dict)}

        def _add(
            title: str,
            severity: str,
            description: str,
            evidence: str,
            remediation: str,
            references: list[str] | None = None,
        ) -> None:
            findings.append(
                {
                    'title': title,
                    'severity': severity,
                    'description': description,
                    'evidence': evidence,
                    'remediation': remediation,
                    'references': references or [],
                }
            )

        if header_lookup.get('strict-transport-security', {}).get('status') == 'WARNING':
            _add(
                'HSTS ausente',
                'medium',
                'El sitio no anuncia Strict-Transport-Security y permite downgrade o navegación HTTP residual.',
                'Header strict-transport-security no presente en respuesta HTTP.',
                'Configurar HSTS con max-age robusto e incluir includeSubDomains/preload donde aplique.',
                ['https://owasp.org/www-project-secure-headers/'],
            )
        if header_lookup.get('content-security-policy', {}).get('status') == 'WARNING':
            _add(
                'CSP ausente',
                'medium',
                'No existe Content-Security-Policy explícita; se reduce capacidad de mitigar XSS y carga de contenido no confiable.',
                'Header content-security-policy no encontrado.',
                'Definir una política CSP inicial en modo report-only y evolucionar a enforcement.',
                ['https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'],
            )
        if header_lookup.get('server', {}).get('status') == 'WARNING':
            _add(
                'Exposición de header Server',
                'low',
                'El banner Server revela tecnología del servidor y facilita fingerprinting atacante.',
                f"Server: {headers_lc.get('server', 'valor no capturado')}",
                'Reducir/anonimizar banner Server mediante hardening de reverse proxy o web server.',
            )
        if header_lookup.get('x-powered-by', {}).get('status') == 'WARNING':
            _add(
                'Exposición de framework vía X-Powered-By',
                'low',
                'El header X-Powered-By filtra framework o runtime de backend.',
                f"X-Powered-By: {headers_lc.get('x-powered-by', 'valor no capturado')}",
                'Deshabilitar X-Powered-By en servidor de aplicaciones o middleware de salida.',
            )

        sensitive = [ep for ep in endpoints if any(token in str(ep.get('path', '')).lower() for token in SENSITIVE_ENDPOINT_TOKENS)]
        for endpoint in sensitive[:6]:
            status = endpoint.get('status_code') or 'n/a'
            sev = 'medium' if status in {200, 401} else 'low'
            _add(
                'Superficie sensible descubierta',
                sev,
                'Se detectó endpoint asociado a administración/autenticación/API que incrementa superficie de ataque.',
                f"{endpoint.get('path')} [{status}] vía {endpoint.get('source', 'enumeration')}",
                'Restringir acceso con segmentación, MFA, allowlist y controles de rate-limit.',
            )

        if redirects:
            redirect_samples = ', '.join([f"{r.get('from', '/') or '/'} -> {r.get('to', '')}" for r in redirects[:3]])
            _add(
                'Redirecciones observables',
                'info',
                'Se observaron redirecciones que pueden revelar lógica interna de routing o zonas administrativas.',
                redirect_samples,
                'Validar que las redirecciones no expongan paths internos y evitar open redirect.',
            )

        insecure_cookies = []
        for cookie in str(headers_lc.get('set-cookie') or '').split(','):
            ck = cookie.strip().lower()
            if ck and ('secure' not in ck or 'httponly' not in ck):
                insecure_cookies.append(cookie.strip())
        if insecure_cookies:
            _add(
                'Cookies sin flags de seguridad completas',
                'medium',
                'Se detectaron cookies sin combinación robusta de flags Secure/HttpOnly/SameSite.',
                '; '.join(insecure_cookies[:3]),
                'Agregar flags Secure, HttpOnly y SameSite apropiadas para cookies de sesión.',
                ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
            )

        if technologies:
            _add(
                'Exposición de tecnologías/frameworks',
                'low',
                'Fingerprinting identificó componentes del stack web visibles externamente.',
                ', '.join(sorted(technologies)[:10]),
                'Minimizar información de versión/banner y reforzar ciclo de parcheo de stack detectado.',
            )
        if cms:
            _add(
                'Superficie CMS detectada',
                'info',
                'Se identificó CMS en la superficie web; requiere hardening específico y monitoreo de plugins/temas.',
                f'CMS detectado: {cms}. Señales: {", ".join(whatweb_signals[:5])}',
                'Aplicar baseline de hardening del CMS y validar inventario/versionado de extensiones.',
            )

        return findings
