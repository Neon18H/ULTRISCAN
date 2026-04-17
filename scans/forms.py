from django import forms

from assets.models import Asset
from scan_profiles.models import ScanProfile


SCAN_TYPE_CHOICES = [
    ('nmap_discovery', 'Infra Discovery'),
    ('nmap_full', 'Infra Standard'),
    ('infra_deep', 'Infra Deep (Opcional)'),
    ('nmap_services', 'Infra Services (Compat)'),
    ('web_basic', 'Web Basic'),
    ('web_full', 'Web Full'),
    ('web_appsec', 'Web AppSec'),
    ('web_wordpress', 'Web WordPress'),
    ('web_api', 'Web API'),
]

SCAN_TYPE_HELP = {
    'nmap_discovery': 'Descubrimiento rápido de hosts y puertos comunes.',
    'nmap_full': 'Escaneo estándar de infraestructura con detección de versiones sobre top ports.',
    'infra_deep': 'Escaneo profundo opcional con más cobertura y mayor tiempo de ejecución.',
    'nmap_services': 'Compatibilidad legacy: usa el perfil estándar de infraestructura.',
    'web_basic': 'Pipeline web base tolerante: fingerprint, headers y checks básicos con fallback.',
    'web_full': 'Pipeline web extendido con mayor enumeración y validaciones adicionales.',
    'web_appsec': 'Pipeline web orientado a appsec (hardening + crawling + templates appsec).',
    'web_wordpress': 'Pipeline web con detección CMS y ejecución WordPress cuando aplique.',
    'web_api': 'Pipeline orientado a superficie API y endpoints dinámicos.',
}

SCAN_TYPE_TO_PROFILE = {
    'nmap_discovery': 'discovery',
    'nmap_full': 'infra_standard',
    'infra_deep': 'infra_deep',
    'nmap_services': 'infra_standard',
    'web_basic': 'web_basic',
    'web_full': 'web_basic',
    'web_appsec': 'web_basic',
    'web_wordpress': 'wordpress',
    'web_api': 'web_basic',
}

WEB_ONLY_SCAN_TYPES = {'web_basic', 'web_full', 'web_appsec', 'web_wordpress', 'web_api'}
PROFILE_NAME_ALIASES = {
    'infra_standard': {'infra_standard', 'full_tcp_safe'},
    'infra_deep': {'infra_deep', 'full'},
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
        self.fields['scan_type'].help_text = 'Selecciona la estrategia más adecuada para el objetivo.'
        for field in self.fields.values():
            css = 'form-select' if isinstance(field, (forms.ModelChoiceField, forms.ChoiceField)) else 'form-control'
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
            'web_basic': 'whatweb+gobuster+nikto',
            'web_full': 'whatweb+ffuf+nuclei+nikto',
            'web_appsec': 'whatweb+ffuf+katana+nuclei+nikto',
            'web_wordpress': 'whatweb+nuclei+wpscan',
            'web_api': 'whatweb+ffuf+nuclei',
        }
        return defaults.get(scan_type, 'nmap')
