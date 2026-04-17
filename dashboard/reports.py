import textwrap
from dataclasses import dataclass, field

from django.http import HttpResponse
from django.utils import timezone


@dataclass
class TextOp:
    text: str
    size: int = 10
    x: int = 48
    y: int = 780
    color: tuple[float, float, float] = (0.06, 0.09, 0.16)


@dataclass
class PDFPage:
    operations: list[TextOp] = field(default_factory=list)


class SimpleEnterprisePDF:
    width = 595
    height = 842

    def __init__(self, title):
        self.title = title
        self.pages = [PDFPage()]
        self.cursor_y = 790

    @property
    def page(self):
        return self.pages[-1]

    def _new_page(self):
        self.pages.append(PDFPage())
        self.cursor_y = 790

    def add_spacer(self, amount=12):
        self.cursor_y -= amount
        if self.cursor_y < 60:
            self._new_page()

    def add_heading(self, text, level=1):
        size = 24 if level == 1 else 15 if level == 2 else 12
        color = (0.06, 0.23, 0.47) if level == 1 else (0.06, 0.09, 0.16)
        self.page.operations.append(TextOp(text=text, size=size, y=self.cursor_y, color=color))
        self.add_spacer(30 if level == 1 else 22)

    def add_line(self, text, size=10, color=(0.12, 0.16, 0.24), x=48):
        self.page.operations.append(TextOp(text=text, size=size, y=self.cursor_y, color=color, x=x))
        self.add_spacer(size + 5)

    def add_rule(self):
        self.add_line('─' * 100, size=9, color=(0.78, 0.82, 0.9))

    def add_table(self, headers, rows, widths=None):
        widths = widths or [18 for _ in headers]
        fmt_header = ' | '.join(str(h).ljust(widths[idx])[: widths[idx]] for idx, h in enumerate(headers))
        self.add_line(fmt_header, size=9, color=(0.06, 0.23, 0.47))
        self.add_line('-' * min(sum(widths) + (3 * (len(widths) - 1)), 112), size=9, color=(0.78, 0.82, 0.9))
        for row in rows:
            rendered = ' | '.join(str(row[idx]).ljust(widths[idx])[: widths[idx]] for idx in range(min(len(row), len(widths))))
            self.add_line(rendered, size=9, color=(0.12, 0.16, 0.24))

    def add_bar_chart(self, title, items, max_width=34):
        self.add_heading(title, level=3)
        max_value = max([int(v) for _, v in items], default=1)
        max_value = max(max_value, 1)
        for label, value in items:
            value_int = int(value or 0)
            bar_len = max(1, int((value_int / max_value) * max_width)) if value_int else 0
            bar = '█' * bar_len if bar_len else '·'
            self.add_line(f'{str(label)[:18].ljust(18)} {str(value_int).rjust(4)}  {bar}', size=9)

    def add_paragraph(self, text, size=10, width=95):
        for line in textwrap.wrap(text, width=width):
            self.add_line(line, size=size)

    def add_kv(self, key, value):
        self.add_line(f'{key}: {value}', size=10)

    def _escape(self, value):
        return value.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

    def render(self):
        objects = []

        def add_object(content):
            objects.append(content)
            return len(objects)

        font_id = add_object('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
        page_ids = []

        for idx, page in enumerate(self.pages, start=1):
            stream_lines = []
            stream_lines.append('0.06 0.09 0.16 rg')
            stream_lines.append('BT /F1 8 Tf 48 24 Td (UltriScan Vulnerability Platform) Tj ET')
            stream_lines.append(f'BT /F1 8 Tf 520 24 Td (Page {idx}) Tj ET')

            for op in page.operations:
                r, g, b = op.color
                stream_lines.append(f'{r:.2f} {g:.2f} {b:.2f} rg')
                stream_lines.append(f'BT /F1 {op.size} Tf {op.x} {op.y} Td ({self._escape(op.text)}) Tj ET')

            stream_data = '\n'.join(stream_lines)
            content_id = add_object(f'<< /Length {len(stream_data.encode("latin-1", errors="replace"))} >>\nstream\n{stream_data}\nendstream')
            page_id = add_object(
                f'<< /Type /Page /Parent 0 0 R /MediaBox [0 0 {self.width} {self.height}] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>'
            )
            page_ids.append(page_id)

        kids_refs = ' '.join(f'{pid} 0 R' for pid in page_ids)
        pages_id = add_object(f'<< /Type /Pages /Kids [{kids_refs}] /Count {len(page_ids)} >>')
        catalog_id = add_object(f'<< /Type /Catalog /Pages {pages_id} 0 R >>')

        updated_objects = []
        for obj in objects:
            updated_objects.append(obj.replace('/Parent 0 0 R', f'/Parent {pages_id} 0 R'))

        pdf = [b'%PDF-1.4\n']
        offsets = [0]
        for i, obj in enumerate(updated_objects, start=1):
            offsets.append(sum(len(part) for part in pdf))
            pdf.append(f'{i} 0 obj\n{obj}\nendobj\n'.encode('latin-1', errors='replace'))

        xref_pos = sum(len(part) for part in pdf)
        pdf.append(f'xref\n0 {len(updated_objects) + 1}\n'.encode('latin-1'))
        pdf.append(b'0000000000 65535 f \n')
        for i in range(1, len(updated_objects) + 1):
            pdf.append(f'{offsets[i]:010d} 00000 n \n'.encode('latin-1'))
        pdf.append(
            f'trailer\n<< /Size {len(updated_objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_pos}\n%%EOF'.encode('latin-1')
        )
        return b''.join(pdf)


def build_executive_summary_pdf(*, organization, findings, assets, scans, generated_by):
    timestamp = timezone.now()
    pdf = SimpleEnterprisePDF('Executive Summary')

    pdf.add_heading('Executive Security Report', level=1)
    pdf.add_paragraph('Resumen ejecutivo de postura de riesgo para comites directivos y clientes enterprise.', size=11)
    pdf.add_spacer(8)
    pdf.add_kv('Organizacion', organization.name)
    pdf.add_kv('Fecha de generacion', timestamp.strftime('%Y-%m-%d %H:%M UTC'))
    pdf.add_kv('Analista', generated_by.get_full_name() or generated_by.email)

    pdf.add_spacer(20)
    pdf.add_heading('Resumen ejecutivo', level=2)
    ai_executive_inputs = [
        finding.ai_summary.strip()
        for finding in findings.order_by('-severity', '-created_at')[:10]
        if finding.ai_summary
    ]
    if ai_executive_inputs:
        pdf.add_paragraph(ai_executive_inputs[0][:420])
    else:
        pdf.add_paragraph(
            'UltriScan consolida los hallazgos de la superficie de ataque y prioriza la remediacion de riesgos criticos. '
            'Este reporte presenta un panorama para toma de decisiones con enfoque en reduccion de exposicion.'
        )

    severity_totals = {level: findings.filter(severity=level).count() for level in ['critical', 'high', 'medium', 'low', 'info']}
    pdf.add_spacer(12)
    pdf.add_heading('KPIs de riesgo', level=2)
    pdf.add_kv('Total findings', findings.count())
    pdf.add_kv('Activos evaluados', assets.count())
    pdf.add_kv('Scans relevantes', scans.count())

    pdf.add_spacer(8)
    pdf.add_heading('Totales por severidad', level=2)
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        pdf.add_kv(sev.upper(), severity_totals[sev])

    pdf.add_spacer(10)
    pdf.add_heading('Top hallazgos recientes', level=2)
    for finding in findings.order_by('-created_at')[:10]:
        pdf.add_paragraph(
            f"- {finding.title} | {finding.get_severity_display()} | {finding.asset.name if finding.asset else 'No asociado'} | {finding.get_status_display()}",
            width=100,
        )

    pdf.add_spacer(10)
    pdf.add_heading('Conclusiones y recomendaciones', level=2)
    ai_recommendations = [finding.ai_remediation for finding in findings.order_by('-severity', '-created_at')[:5] if finding.ai_remediation]
    if ai_recommendations:
        for idx, recommendation in enumerate(ai_recommendations[:3], start=1):
            pdf.add_paragraph(f'{idx}) {recommendation[:420]}')
    else:
        pdf.add_paragraph('1) Atender findings Critical/High en ventanas maximas de 7 dias con validacion de cierre.')
        pdf.add_paragraph('2) Reducir servicios expuestos innecesarios y fortalecer hardening de activos internet-facing.')
        pdf.add_paragraph('3) Ejecutar escaneos recurrentes y seguimiento de SLA de remediacion por severidad.')

    filename = f"ultriscan_executive_summary_{organization.slug}_{timestamp.strftime('%Y%m%d_%H%M')}.pdf"
    response = HttpResponse(pdf.render(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def build_technical_findings_pdf(*, organization, findings, generated_by, applied_filters):
    timestamp = timezone.now()
    pdf = SimpleEnterprisePDF('Technical Findings')

    pdf.add_heading('Technical Findings Report', level=1)
    pdf.add_paragraph('Detalle tecnico de evidencia, estado y remediacion para equipos de ciberseguridad.', size=11)
    pdf.add_spacer(8)
    pdf.add_kv('Organizacion', organization.name)
    pdf.add_kv('Fecha de generacion', timestamp.strftime('%Y-%m-%d %H:%M UTC'))
    pdf.add_kv('Analista', generated_by.get_full_name() or generated_by.email)
    if applied_filters:
        pdf.add_kv('Filtros aplicados', ' | '.join([f"{item['label']}: {item['value']}" for item in applied_filters]))
    else:
        pdf.add_kv('Filtros aplicados', 'Ninguno')

    pdf.add_spacer(10)
    pdf.add_heading('Resumen de alcance', level=2)
    pdf.add_kv('Findings incluidos', findings.count())
    pdf.add_kv('Activos impactados', findings.exclude(asset__isnull=True).values('asset_id').distinct().count())

    pdf.add_spacer(10)
    pdf.add_heading('Listado de findings', level=2)
    for finding in findings[:200]:
        service_port = 'N/A'
        if finding.service_finding:
            service_port = f"{finding.service_finding.service or 'n/a'}:{finding.service_finding.port or '-'}"

        pdf.add_line(f"{finding.ai_title or finding.title}", size=11, color=(0.06, 0.23, 0.47))
        pdf.add_paragraph(
            f"Severidad: {finding.get_severity_display()} | Estado: {finding.get_status_display()} | "
            f"Confidence: {finding.get_confidence_display()} | Activo: {finding.asset.name if finding.asset else 'No asociado'} | "
            f"Servicio/Puerto: {service_port}",
            width=102,
        )
        pdf.add_paragraph(f"Evidencia: {(finding.ai_summary or finding.description or 'Sin evidencia')[:420]}", width=102)
        pdf.add_paragraph(f"Impacto: {(finding.ai_impact or 'Sin impacto enriquecido')[:420]}", width=102)
        pdf.add_paragraph(f"Priorizacion: {(finding.ai_priority_reason or 'Sin razonamiento IA')[:420]}", width=102)
        pdf.add_paragraph(f"Remediacion: {(finding.ai_remediation or finding.remediation or 'Sin remediacion definida')[:420]}", width=102)
        if finding.ai_owasp_category or finding.ai_cwe:
            pdf.add_paragraph(
                f"OWASP/CWE: {finding.ai_owasp_category or '-'} / {finding.ai_cwe or '-'}",
                width=102,
            )
        pdf.add_paragraph(f"Referencia: {finding.reference or 'Sin referencia'}", width=102)
        pdf.add_spacer(10)

    filename = f"ultriscan_technical_findings_{organization.slug}_{timestamp.strftime('%Y%m%d_%H%M')}.pdf"
    response = HttpResponse(pdf.render(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def build_scan_report_pdf(*, scan, generated_by):
    timestamp = timezone.now()
    summary = scan.summary if isinstance(scan.summary, dict) else {}
    engine_metadata = scan.engine_metadata if isinstance(scan.engine_metadata, dict) else {}
    structured = engine_metadata.get('structured_results') if isinstance(engine_metadata.get('structured_results'), dict) else {}
    tools = structured.get('tools') if isinstance(structured.get('tools'), dict) else {}
    findings = list(scan.findings.all().order_by('-severity', '-created_at')[:150])

    pdf = SimpleEnterprisePDF(f'Scan Report #{scan.id}')
    scan_type = structured.get('scan_type') or summary.get('scan_type') or 'n/a'
    target = structured.get('target') or scan.asset.value
    technologies = structured.get('technologies') or []
    endpoints = structured.get('endpoints') or []
    vulns = structured.get('vulnerabilities') or []
    interpreted_headers = structured.get('interpreted_headers') or []
    appsec = structured.get('appsec') if isinstance(structured.get('appsec'), dict) else {}

    severity_totals = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for vuln in vulns:
        sev = (vuln.get('severity') or 'medium').lower()
        if sev not in severity_totals:
            sev = 'info'
        severity_totals[sev] += 1
    risk_level = 'LOW'
    if severity_totals['critical'] > 0:
        risk_level = 'CRITICAL'
    elif severity_totals['high'] > 0:
        risk_level = 'HIGH'
    elif severity_totals['medium'] > 0:
        risk_level = 'MEDIUM'

    web_findings = structured.get('web_findings') or structured.get('web_findings_basic') or []
    module_status = structured.get('module_status') or {}

    # 1. Cover
    pdf.add_heading('UltriScan', level=1)
    pdf.add_paragraph('Enterprise Vulnerability Assessment Report', size=11)
    pdf.add_rule()
    pdf.add_spacer(8)
    pdf.add_kv('Tipo de scan', scan_type)
    pdf.add_kv('Objetivo', target)
    pdf.add_kv('Organización', scan.organization.name)
    pdf.add_kv('Fecha', scan.created_at.strftime('%Y-%m-%d %H:%M UTC'))
    pdf.add_kv('Generado por', generated_by.get_full_name() or generated_by.email)
    pdf.add_kv('Nivel de riesgo observado', risk_level)
    pdf.add_spacer(8)
    pdf.add_paragraph('Documento orientado a comités técnicos y operaciones de seguridad con foco en remediación accionable.')

    # 2. TOC
    pdf._new_page()
    pdf.add_heading('Tabla de contenido', level=2)
    for section in [
        '1. Portada',
        '2. Tabla de contenido',
        '3. Resumen ejecutivo',
        '4. Metodología',
        '5. Resultados técnicos',
        '6. Hallazgos detallados',
        '7. Recomendaciones',
        '8. Metadata técnica',
    ]:
        pdf.add_paragraph(section, width=95)

    # 3. Executive summary
    pdf._new_page()
    pdf.add_heading('Resumen ejecutivo', level=2)
    pdf.add_paragraph(
        'Se evaluó la superficie de exposición del objetivo para identificar riesgos técnicos, '
        'rutas sensibles y vulnerabilidades con impacto potencial en confidencialidad, integridad y disponibilidad.'
    )
    pdf.add_kv('Resultado general', scan.get_status_display())
    pdf.add_kv('Findings correlacionados', len(findings))
    pdf.add_kv('Tecnologías detectadas', len(technologies))
    pdf.add_kv('Endpoints descubiertos', len(endpoints))
    pdf.add_kv('Vulnerabilidades detectadas', len(vulns))
    pdf.add_kv('Controles de seguridad evaluados', len(interpreted_headers))
    pdf.add_paragraph(
        f"Resumen de severidad: Critical={severity_totals['critical']}, High={severity_totals['high']}, "
        f"Medium={severity_totals['medium']}, Low={severity_totals['low']}, Info={severity_totals['info']}."
    )
    pdf.add_table(
        ['KPI', 'Valor', 'Contexto'],
        [
            ['Controles presentes', structured.get('web_kpis', {}).get('controls_present', 0), 'Hardening activo detectado.'],
            ['Controles ausentes', structured.get('web_kpis', {}).get('controls_absent', 0), 'Brechas de configuración base.'],
            ['Exposición tecnológica', structured.get('web_kpis', {}).get('exposure_observed', 0), 'Información útil para fingerprinting.'],
            ['Score scan web', f"{structured.get('web_kpis', {}).get('score', 'n/a')}/100", 'Indicador agregado de postura web.'],
        ],
        widths=[26, 12, 62],
    )

    # 4. Methodology
    pdf.add_spacer(12)
    pdf.add_heading('Metodología', level=2)
    pdf.add_paragraph('Herramientas utilizadas: WhatWeb, Gobuster/FFUF, Nuclei, Nikto, WPScan (según disponibilidad).')
    pdf.add_paragraph('Proceso aplicado: fingerprinting, enumeración de endpoints, evaluación de vulnerabilidades, correlación de findings.')
    pdf.add_paragraph(f"Alcance del scan: {scan_type} sobre {target}.")
    if scan_type == 'web_appsec':
        pdf.add_paragraph(
            f"Configuración AppSec: agresividad={structured.get('aggressiveness', 'medium')} | "
            f"módulos={', '.join(structured.get('modules_selected') or []) or 'n/a'}."
        )
    if structured.get('partial_result') or summary.get('partial_result'):
        pdf.add_paragraph('Limitaciones detectadas: ejecución parcial por dependencias faltantes, timeouts o límites del worker.')
    if structured.get('warnings'):
        pdf.add_paragraph(f"Warnings relevantes: {' | '.join(structured.get('warnings')[:6])}", width=100)

    # 5. Technical results + charts
    pdf._new_page()
    pdf.add_heading('Resultados técnicos', level=2)
    fingerprint = structured.get('fingerprint') or {}
    pdf.add_kv('HTTP status objetivo', structured.get('http_status') or 'n/a')
    pdf.add_kv('Servidor detectado', fingerprint.get('server') or 'n/a')
    pdf.add_kv('IP detectada', fingerprint.get('ip') or 'n/a')
    pdf.add_kv('País detectado', fingerprint.get('country') or 'n/a')
    if technologies:
        pdf.add_spacer(10)
        pdf.add_heading('Tecnologías detectadas', level=2)
        pdf.add_paragraph(', '.join(technologies[:40]), width=104)
    pdf.add_spacer(8)
    pdf.add_bar_chart('Gráfico · Hallazgos por severidad', [(sev.upper(), total) for sev, total in severity_totals.items()])
    endpoint_status = structured.get('endpoints_by_status') or {}
    if endpoint_status:
        pdf.add_spacer(6)
        pdf.add_bar_chart('Gráfico · Endpoints por status', list(endpoint_status.items())[:8], max_width=26)
    pdf.add_spacer(10)
    pdf.add_heading('Endpoints encontrados', level=2)
    if endpoints:
        for endpoint in endpoints[:60]:
            pdf.add_paragraph(
                f"- {endpoint.get('path') or endpoint.get('url')} | Status: {endpoint.get('status_code', 'n/a')} | "
                f"Redirect: {endpoint.get('redirect') or '-'} | Source: {endpoint.get('source', 'n/a')} | "
                f"Prioridad: {(endpoint.get('priority') or 'low').upper()}",
                width=104,
            )
    else:
        pdf.add_paragraph('No se identificaron endpoints relevantes.')

    redirects = structured.get('redirects') or []
    if redirects:
        pdf.add_spacer(10)
        pdf.add_heading('Redirecciones detectadas', level=2)
        for redirect in redirects[:20]:
            pdf.add_paragraph(f'- {redirect}', width=102)

    pdf.add_spacer(10)
    pdf.add_heading('Headers y observaciones de seguridad', level=2)
    if interpreted_headers:
        for row in interpreted_headers[:25]:
            pdf.add_paragraph(
                f"- [{row.get('status')}] {row.get('header')}: {row.get('message')}",
                width=104,
            )
    else:
        pdf.add_paragraph('Sin observaciones de headers.')

    pdf.add_spacer(10)
    if module_status:
        pdf.add_heading('Herramientas ejecutadas/omitidas', level=2)
        pdf.add_table(
            ['Estado módulo', 'Cantidad', 'Detalle'],
            [
                ['OK', module_status.get('ok', 0), ', '.join(tools.get('executed') or []) or 'N/A'],
                ['Warning', module_status.get('warning', 0), 'Ejecución con alertas o cobertura parcial'],
                ['Failed', module_status.get('failed', 0), ', '.join([r.get('tool', '') for r in tools.get('failed') or []]) or 'N/A'],
                ['Skipped', module_status.get('skipped', 0), ', '.join([r.get('tool', '') for r in tools.get('skipped') or []]) or 'N/A'],
            ],
            widths=[20, 10, 70],
        )
        pdf.add_spacer(8)

    pdf.add_heading('Vulnerabilidades detectadas', level=2)
    if vulns:
        for vuln in vulns[:80]:
            pdf.add_paragraph(
                f"- {vuln.get('name', 'Vulnerability')} | Severidad: {(vuln.get('severity') or 'medium').upper()} | "
                f"Fuente: {vuln.get('type', 'n/a')} | Evidencia: {vuln.get('matched_at') or 'n/a'}",
                width=104,
            )
    else:
        pdf.add_paragraph('No se detectaron vulnerabilidades en el alcance evaluado.')

    if scan_type == 'web_appsec':
        pdf.add_spacer(8)
        pdf.add_heading('Resultados AppSec por familia', level=2)
        families = appsec.get('findings_by_family') or {}
        if families:
            rows = [[family.upper(), len(items)] for family, items in families.items()]
            pdf.add_table(['Familia', 'Total'], rows, widths=[60, 20])
        else:
            pdf.add_paragraph('Sin resultados AppSec por familia.')
        suspicious = appsec.get('suspicious_parameters') or []
        if suspicious:
            pdf.add_spacer(6)
            pdf.add_heading('Parámetros sospechosos', level=3)
            for row in suspicious[:30]:
                pdf.add_paragraph(f"- {row.get('parameter')} @ {row.get('url')}", width=104)

    # 6. Findings
    pdf._new_page()
    pdf.add_heading('Findings priorizados', level=2)
    if web_findings:
        pdf.add_heading('Hallazgos web de configuración', level=3)
        web_rows = []
        for finding in web_findings[:20]:
            web_rows.append(
                [
                    finding.get('title', 'Web finding'),
                    str(finding.get('severity', 'info')).upper(),
                    (finding.get('evidence') or '-')[:46],
                    (finding.get('remediation') or '-')[:46],
                ]
            )
        pdf.add_table(['Hallazgo', 'Sev', 'Evidencia', 'Remediación'], web_rows, widths=[28, 8, 32, 32])
        pdf.add_spacer(10)
    if findings:
        for finding in findings[:80]:
            pdf.add_paragraph(
                f"- {finding.title} | Severidad: {finding.get_severity_display()} | Estado: {finding.get_status_display()}",
                width=104,
            )
            if finding.remediation:
                pdf.add_paragraph(f"  Remediación: {finding.remediation[:220]}", width=100)
    else:
        pdf.add_paragraph('No existen findings correlacionados para este scan.')

    # 7. Recommendations
    pdf.add_spacer(10)
    pdf.add_heading('Recomendaciones', level=2)
    pdf.add_paragraph('Quick wins: activar HSTS/CSP, ocultar Server/X-Powered-By, y endurecer cookies de sesión.')
    pdf.add_paragraph('Prioridad alta: reducir superficie de login/admin y revisar rutas sensibles con controles de acceso.')
    pdf.add_paragraph('AppSec: aplicar validaciones anti-XSS/SQLi, WAF/rate-limiting y monitoreo de redirecciones.')
    pdf.add_paragraph('Operación: repetir escaneo tras remediación y validar cierre con evidencia técnica.')

    # 8. Technical metadata
    pdf.add_spacer(10)
    pdf.add_heading('Metadata técnica', level=2)
    pdf.add_kv('Scan ID', scan.id)
    pdf.add_kv('Comando(s)', (scan.command_executed or 'n/a')[:220])
    pdf.add_kv('Worker status', scan.get_status_display())
    pdf.add_kv('Duración (s)', scan.duration_seconds or 0)
    pdf.add_kv('Módulos ejecutados', ', '.join(tools.get('executed') or []) or 'N/A')
    pdf.add_kv('Módulos omitidos', ', '.join([row.get('tool', '') for row in tools.get('skipped') or []]) or 'N/A')

    filename = f"ultriscan_scan_{scan.id}_{timestamp.strftime('%Y%m%d_%H%M')}.pdf"
    response = HttpResponse(pdf.render(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
