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

        pdf.add_line(f"{finding.title}", size=11, color=(0.06, 0.23, 0.47))
        pdf.add_paragraph(
            f"Severidad: {finding.get_severity_display()} | Estado: {finding.get_status_display()} | "
            f"Confidence: {finding.get_confidence_display()} | Activo: {finding.asset.name if finding.asset else 'No asociado'} | "
            f"Servicio/Puerto: {service_port}",
            width=102,
        )
        pdf.add_paragraph(f"Evidencia: {(finding.description or 'Sin evidencia')[:420]}", width=102)
        pdf.add_paragraph(f"Remediacion: {(finding.remediation or 'Sin remediacion definida')[:420]}", width=102)
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
    pdf.add_heading('UltriScan', level=1)
    pdf.add_paragraph('Enterprise Cyber Exposure Report', size=11)
    pdf.add_spacer(8)
    pdf.add_kv('Tipo de scan', structured.get('scan_type') or summary.get('scan_type') or 'n/a')
    pdf.add_kv('Objetivo', structured.get('target') or scan.asset.value)
    pdf.add_kv('Estado', scan.get_status_display())
    pdf.add_kv('Fecha', scan.created_at.strftime('%Y-%m-%d %H:%M UTC'))
    pdf.add_kv('Analista', generated_by.get_full_name() or generated_by.email)

    pdf.add_spacer(14)
    pdf.add_heading('Resumen ejecutivo', level=2)
    pdf.add_paragraph(
        'Este reporte resume el estado de exposición del objetivo escaneado, incluyendo evidencias técnicas, '
        'hallazgos priorizados y recomendaciones accionables.'
    )
    pdf.add_kv('Findings', len(findings))
    pdf.add_kv('Tecnologías detectadas', len(structured.get('technologies') or []))
    pdf.add_kv('Endpoints descubiertos', len(structured.get('endpoints') or []))
    pdf.add_kv('Vulnerabilidades detectadas', len(structured.get('vulnerabilities') or []))

    pdf.add_spacer(10)
    pdf.add_heading('Herramientas ejecutadas', level=2)
    pdf.add_paragraph(f"Ejecutadas: {', '.join(tools.get('executed') or []) or 'Sin ejecuciones exitosas'}")
    pdf.add_paragraph(
        f"Omitidas/Fallidas: {len(tools.get('skipped') or []) + len(tools.get('failed') or [])} | "
        f"Warnings: {len(structured.get('warnings') or [])}"
    )

    technologies = structured.get('technologies') or []
    if technologies:
        pdf.add_spacer(10)
        pdf.add_heading('Tecnologías detectadas', level=2)
        pdf.add_paragraph(', '.join(technologies[:40]), width=104)

    endpoints = structured.get('endpoints') or []
    pdf.add_spacer(10)
    pdf.add_heading('Endpoints encontrados', level=2)
    if endpoints:
        for endpoint in endpoints[:60]:
            pdf.add_paragraph(
                f"- {endpoint.get('path') or endpoint.get('url')} | Status: {endpoint.get('status_code', 'n/a')} | Source: {endpoint.get('source', 'n/a')}",
                width=104,
            )
    else:
        pdf.add_paragraph('No se identificaron endpoints relevantes.')

    interpreted_headers = structured.get('interpreted_headers') or []
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

    vulns = structured.get('vulnerabilities') or []
    pdf.add_spacer(10)
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

    pdf.add_spacer(10)
    pdf.add_heading('Findings priorizados', level=2)
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

    pdf.add_spacer(10)
    pdf.add_heading('Recomendaciones', level=2)
    pdf.add_paragraph('1) Priorizar la remediación de severidades Critical/High en menos de 7 días.')
    pdf.add_paragraph('2) Aplicar hardening de headers y reducir exposición de endpoints administrativos.')
    pdf.add_paragraph('3) Repetir escaneo tras remediación para validar cierre técnico.')

    pdf.add_spacer(10)
    pdf.add_heading('Metadata técnica', level=2)
    pdf.add_kv('Scan ID', scan.id)
    pdf.add_kv('Comando(s)', (scan.command_executed or 'n/a')[:180])
    pdf.add_kv('Worker status', scan.get_status_display())
    pdf.add_kv('Duración (s)', scan.duration_seconds or 0)

    filename = f"ultriscan_scan_{scan.id}_{timestamp.strftime('%Y%m%d_%H%M')}.pdf"
    response = HttpResponse(pdf.render(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
