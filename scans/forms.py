from django import forms

from assets.models import Asset
from scan_profiles.models import ScanProfile


SCAN_TYPE_CHOICES = [
    ('nmap_discovery', 'Infra Discovery'),
    ('nmap_full', 'Infra Standard'),
    ('infra_deep', 'Infra Deep (Opcional)'),
    ('nmap_services', 'Infra Services (Compat)'),
    ('web_basic', 'Web Basic'),
    ('web_misconfig', 'Web Misconfig'),
    ('web_full', 'Web Full'),
    ('web_appsec', 'Web AppSec'),
    ('web_wordpress', 'Web WordPress'),
    ('web_api', 'Web API'),
]

WEB_APPSEC_MODULE_CHOICES = [
    ('xss', 'XSS'),
    ('sqli', 'SQL Injection'),
    ('misconfig', 'Security Misconfiguration / Review'),
    ('csrf', 'CSRF Review'),
    ('idor', 'Broken Access Control / IDOR surface'),
    ('auth', 'Broken Authentication surface'),
    ('upload', 'File Upload surface'),
    ('ssrf', 'SSRF surface'),
    ('endpoint_discovery', 'Endpoint Discovery / Hidden APIs'),
]

WEB_APPSEC_MODULE_DETAILS = {
    'xss': {
        'description': 'Detecta reflejos de payloads y señales de Cross-Site Scripting.',
        'tool': 'dalfox',
        'impact': 'Ejecución de JavaScript malicioso, secuestro de sesión y defacement.',
        'severity': 'high',
    },
    'sqli': {
        'description': 'Identifica parámetros potencialmente inyectables sobre endpoints dinámicos.',
        'tool': 'sqlmap',
        'impact': 'Exfiltración, alteración o destrucción de datos en base de datos.',
        'severity': 'critical',
    },
    'auth': {
        'description': 'Revisa superficies de autenticación débil y puntos de acceso sensibles.',
        'tool': 'httpx + revisión de flujos',
        'impact': 'Acceso no autorizado y toma de cuentas.',
        'severity': 'high',
    },
    'idor': {
        'description': 'Mapea indicadores de control de acceso insuficiente entre recursos.',
        'tool': 'katana + revisión heurística',
        'impact': 'Exposición o modificación de datos de otros usuarios.',
        'severity': 'high',
    },
    'csrf': {
        'description': 'Marca formularios y acciones críticas que requieren validación anti-CSRF.',
        'tool': 'análisis de formularios + revisión estructural',
        'impact': 'Ejecución de acciones no autorizadas en contexto de víctima autenticada.',
        'severity': 'medium',
    },
    'ssrf': {
        'description': 'Evalúa superficie de SSRF en entradas con URLs, webhooks o fetch remotos.',
        'tool': 'enumeración de parámetros y endpoints',
        'impact': 'Acceso a red interna, metadata cloud y pivote lateral.',
        'severity': 'high',
    },
    'endpoint_discovery': {
        'description': 'Descubre rutas ocultas, APIs internas y endpoints no documentados.',
        'tool': 'katana + ffuf',
        'impact': 'Ampliación de superficie de ataque y exposición de funcionalidades sensibles.',
        'severity': 'medium',
    },
    'upload': {
        'description': 'Revisa puntos de carga de archivos y validaciones de tipo/contenido.',
        'tool': 'enumeración de formularios y endpoints',
        'impact': 'Subida de archivos maliciosos, web shells o bypass de controles.',
        'severity': 'high',
    },
    'misconfig': {
        'description': 'Busca desviaciones de hardening, headers débiles y configuraciones inseguras.',
        'tool': 'zap-baseline.py + nuclei/nikto',
        'impact': 'Incremento del riesgo global por controles de seguridad mal aplicados.',
        'severity': 'medium',
    },
}

WEB_APPSEC_MODULE_GROUPS = [
    {
        'id': 'injection-attacks',
        'name': 'Injection Attacks',
        'icon': 'bi-bug',
        'modules': ['xss', 'sqli'],
    },
    {
        'id': 'authentication-access',
        'name': 'Authentication & Access',
        'icon': 'bi-shield-lock',
        'modules': ['auth', 'idor'],
    },
    {
        'id': 'application-logic',
        'name': 'Application Logic',
        'icon': 'bi-diagram-3',
        'modules': ['csrf', 'ssrf'],
    },
    {
        'id': 'discovery-surface',
        'name': 'Discovery & Surface',
        'icon': 'bi-binoculars',
        'modules': ['endpoint_discovery', 'upload'],
    },
    {
        'id': 'security-misconfiguration',
        'name': 'Security Misconfiguration',
        'icon': 'bi-sliders2',
        'modules': ['misconfig'],
    },
]

WEB_APPSEC_AGGRESSIVENESS_CHOICES = [
    ('low', 'Low'),
    ('medium', 'Medium'),
    ('high', 'High'),
]

WEB_SCAN_PRESETS = {
    'low': {
        'rate_limit': 2,
        'concurrency': 1,
        'max_depth': 2,
        'max_endpoints': 120,
        'module_timeout': 120,
    },
    'medium': {
        'rate_limit': 4,
        'concurrency': 2,
        'max_depth': 3,
        'max_endpoints': 320,
        'module_timeout': 180,
    },
    'high': {
        'rate_limit': 8,
        'concurrency': 3,
        'max_depth': 4,
        'max_endpoints': 700,
        'module_timeout': 300,
    },
}

SCAN_TYPE_HELP = {
    'nmap_discovery': 'Descubrimiento rápido de hosts y puertos comunes.',
    'nmap_full': 'Escaneo estándar de infraestructura con detección de versiones sobre top ports.',
    'infra_deep': 'Escaneo profundo opcional con más cobertura y mayor tiempo de ejecución.',
    'nmap_services': 'Compatibilidad legacy: usa el perfil estándar de infraestructura.',
    'web_basic': 'Pipeline web ligero: fingerprint, headers, tecnologías, endpoints y exposición básica.',
    'web_misconfig': 'Pipeline web de hardening/misconfig (headers, nikto, nuclei misconfig, cookies/redirects/banners).',
    'web_full': 'Pipeline web extendido con mayor enumeración y validaciones adicionales.',
    'web_appsec': 'Pipeline AppSec modular (XSS/SQLi/CSRF/IDOR/Auth/Upload/SSRF/Discovery) con controles de agresividad.',
    'web_wordpress': 'Pipeline web con detección CMS y ejecución WordPress cuando aplique.',
    'web_api': 'Pipeline orientado a superficie API y endpoints dinámicos.',
}

SCAN_TYPE_TO_PROFILE = {
    'nmap_discovery': 'discovery',
    'nmap_full': 'infra_standard',
    'infra_deep': 'infra_deep',
    'nmap_services': 'infra_standard',
    'web_basic': 'web_basic',
    'web_misconfig': 'web_misconfig',
    'web_full': 'web_basic',
    'web_appsec': 'web_appsec',
    'web_wordpress': 'wordpress',
    'web_api': 'web_basic',
}

WEB_ONLY_SCAN_TYPES = {'web_basic', 'web_misconfig', 'web_full', 'web_appsec', 'web_wordpress', 'web_api'}
PROFILE_NAME_ALIASES = {
    'infra_standard': {'infra_standard', 'full_tcp_safe'},
    'infra_deep': {'infra_deep', 'full'},
    'web_misconfig': {'web_misconfig', 'misconfiguration'},
}


class CreateScanForm(forms.Form):
    asset = forms.ModelChoiceField(queryset=Asset.objects.none(), label='Activo objetivo')
    scan_type = forms.ChoiceField(choices=SCAN_TYPE_CHOICES, label='Tipo de escaneo')
    profile = forms.ModelChoiceField(queryset=ScanProfile.objects.none(), label='Perfil de escaneo')
    module = forms.CharField(label='Herramienta / módulo', required=False, max_length=80)
    options = forms.CharField(
        label='Opciones básicas',
        required=False,
        widget=forms.Textarea(attrs={'rows': 3, 'placeholder': 'Ej: top-ports=1000, timeout=120s'}),
    )
    web_appsec_aggressiveness = forms.ChoiceField(
        label='Agresividad AppSec',
        required=False,
        choices=WEB_APPSEC_AGGRESSIVENESS_CHOICES,
        initial='medium',
    )
    web_appsec_modules = forms.MultipleChoiceField(
        label='Módulos AppSec',
        required=False,
        choices=WEB_APPSEC_MODULE_CHOICES,
        widget=forms.CheckboxSelectMultiple,
        initial=[choice[0] for choice in WEB_APPSEC_MODULE_CHOICES],
    )
    web_rate_limit = forms.IntegerField(label='Rate limit (req/s)', required=False, min_value=1, max_value=200)
    web_concurrency = forms.IntegerField(label='Concurrencia', required=False, min_value=1, max_value=50)
    web_max_depth = forms.IntegerField(label='Profundidad máxima', required=False, min_value=1, max_value=10)
    web_max_endpoints = forms.IntegerField(label='Máximo endpoints', required=False, min_value=10, max_value=20000)
    web_module_timeout = forms.IntegerField(label='Timeout por módulo (s)', required=False, min_value=10, max_value=1800)
    web_excluded_paths = forms.CharField(
        label='Excluir paths (coma-separados)',
        required=False,
        widget=forms.TextInput(attrs={'placeholder': '/logout,/static,/health'}),
    )
    web_allowlist_domains = forms.CharField(
        label='Allowlist dominios (coma-separados)',
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'example.com,api.example.com'}),
    )
    web_authenticated_mode = forms.BooleanField(label='Modo autenticado', required=False)

    def __init__(self, *args, organization=None, initial_asset=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.organization = organization
        if organization:
            self.fields['asset'].queryset = Asset.objects.filter(organization=organization).order_by('name')
            self.fields['profile'].queryset = ScanProfile.objects.filter(organization=organization).order_by('name')
        self.fields['asset'].empty_label = 'Selecciona un activo'
        self.fields['profile'].empty_label = 'Selecciona un perfil'
        if initial_asset:
            self.fields['asset'].initial = initial_asset
        medium_defaults = WEB_SCAN_PRESETS['medium']
        self.fields['web_rate_limit'].initial = medium_defaults['rate_limit']
        self.fields['web_concurrency'].initial = medium_defaults['concurrency']
        self.fields['web_max_depth'].initial = medium_defaults['max_depth']
        self.fields['web_max_endpoints'].initial = medium_defaults['max_endpoints']
        self.fields['web_module_timeout'].initial = medium_defaults['module_timeout']
        self.fields['scan_type'].help_text = 'Selecciona la estrategia más adecuada para el objetivo.'
        for name, field in self.fields.items():
            css = 'form-select' if isinstance(field, (forms.ModelChoiceField, forms.ChoiceField)) else 'form-control'
            if isinstance(field.widget, forms.CheckboxSelectMultiple):
                field.widget.attrs.update({'class': 'form-check-input'})
                continue
            if isinstance(field, forms.BooleanField):
                field.widget.attrs.update({'class': 'form-check-input'})
                continue
            field.widget.attrs.update({'class': css})

    def clean(self):
        cleaned = super().clean()
        asset = cleaned.get('asset')
        profile = cleaned.get('profile')
        scan_type = cleaned.get('scan_type')

        if not asset or not scan_type:
            return cleaned

        if asset.asset_type in {Asset.AssetType.IP, Asset.AssetType.CIDR} and scan_type in WEB_ONLY_SCAN_TYPES:
            self.add_error('scan_type', 'Este tipo de activo no aplica para escaneos web. Usa dominio o URL.')

        expected_profile_name = SCAN_TYPE_TO_PROFILE.get(scan_type)
        accepted_profile_names = PROFILE_NAME_ALIASES.get(expected_profile_name, {expected_profile_name}) if expected_profile_name else set()
        if profile and expected_profile_name and profile.name.lower() not in accepted_profile_names:
            self.add_error('profile', f'El perfil seleccionado no corresponde al tipo de escaneo: {expected_profile_name}.')

        if self.organization:
            if asset.organization_id != self.organization.id:
                self.add_error('asset', 'Activo fuera de la organización activa.')
            if profile and profile.organization_id != self.organization.id:
                self.add_error('profile', 'Perfil fuera de la organización activa.')

        if scan_type == 'web_appsec' and not cleaned.get('web_appsec_modules'):
            self.add_error('web_appsec_modules', 'Selecciona al menos un módulo para web_appsec.')

        return cleaned

    def clean_module(self):
        module = (self.cleaned_data.get('module') or '').strip()
        scan_type = self.cleaned_data.get('scan_type')
        if module:
            return module
        defaults = {
            'nmap_discovery': 'nmap',
            'nmap_full': 'nmap',
            'infra_deep': 'nmap+nse',
            'nmap_services': 'nmap',
            'web_basic': 'whatweb+gobuster+nikto+nuclei',
            'web_misconfig': 'whatweb+nikto+nuclei+httpx',
            'web_full': 'whatweb+ffuf+nuclei+nikto+katana',
            'web_appsec': 'httpx+katana+ffuf+nuclei+dalfox+sqlmap+zap',
            'web_wordpress': 'whatweb+nuclei+wpscan',
            'web_api': 'whatweb+ffuf+nuclei',
        }
        return defaults.get(scan_type, 'nmap')

    @staticmethod
    def parse_csv_field(raw_value: str | None) -> list[str]:
        return [item.strip() for item in (raw_value or '').split(',') if item.strip()]
