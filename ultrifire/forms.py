from django import forms

from .models import ProviderArtifact
from .providers import provider_choices
from .services import PolicyValidationError, validate_policy

POLICY_TYPE_CHOICES = [
    ('outbound_allow', 'Permitir salida LAN/Internet'),
    ('inbound_publish', 'Publicar servicio interno'),
    ('interzone', 'Tráfico entre zonas'),
    ('blocklist', 'Bloqueo'),
]


class PolicyForm(forms.Form):
    policy_type = forms.ChoiceField(label='Tipo de política', choices=POLICY_TYPE_CHOICES)
    name = forms.CharField(label='Nombre', max_length=160)
    enabled = forms.BooleanField(label='Habilitada', required=False, initial=True)
    description = forms.CharField(label='Descripción', required=False, widget=forms.Textarea(attrs={'rows': 2}))
    provider = forms.ChoiceField(label='Provider / origen del recurso', choices=provider_choices(), required=False)
    cloud_resource_id = forms.ModelChoiceField(label='Recurso cloud registrado', queryset=ProviderArtifact.objects.none(), required=False)
    resource_name = forms.CharField(label='Nombre del recurso', max_length=160, required=False)
    resource_type = forms.CharField(label='Tipo de recurso', max_length=80, required=False, initial='ec2')
    region = forms.CharField(label='Región', max_length=80, required=False)
    inbound_interface = forms.CharField(label='Interfaz de entrada', max_length=64, required=False, initial='lan')
    source_zone = forms.CharField(label='Zona/interfaz origen', max_length=64, required=False)
    destination_zone = forms.CharField(label='Zona/interfaz destino', max_length=64, required=False)
    source = forms.CharField(label='Origen', max_length=255, required=False, initial='any')
    destination = forms.CharField(label='Destino', max_length=255, required=False, initial='any')
    protocol = forms.ChoiceField(label='Protocolo', choices=[('tcp', 'TCP'), ('udp', 'UDP'), ('icmp', 'ICMP'), ('any', 'Any')], required=False, initial='tcp')
    destination_port = forms.CharField(label='Puerto destino', max_length=32, required=False, initial='any')
    public_address = forms.CharField(label='Dirección pública', max_length=255, required=False, initial='wan_address')
    public_port = forms.CharField(label='Puerto público', max_length=32, required=False)
    backend_ip = forms.GenericIPAddressField(label='IP privada backend', required=False)
    backend_port = forms.CharField(label='Puerto backend', max_length=32, required=False)
    allowed_sources = forms.CharField(label='Orígenes permitidos', required=False, initial='any', help_text='any o lista CIDR/IP separada por comas')
    nat_enabled = forms.BooleanField(label='NAT habilitado', required=False, initial=True)
    create_firewall_pass_rule = forms.BooleanField(label='Crear regla pass asociada', required=False, initial=True)
    action = forms.ChoiceField(label='Acción', choices=[('pass', 'Pass'), ('block', 'Block'), ('reject', 'Reject')], required=False, initial='pass')
    schedule = forms.CharField(label='Schedule', max_length=120, required=False)
    reason = forms.CharField(label='Motivo', required=False, widget=forms.Textarea(attrs={'rows': 2}))

    def __init__(self, *args, organization=None, **kwargs):
        self.organization = organization
        super().__init__(*args, **kwargs)
        self.fields['cloud_resource_id'].queryset = ProviderArtifact.objects.filter(organization=organization) if organization else ProviderArtifact.objects.none()
        for field in self.fields.values():
            css = 'form-select' if isinstance(field.widget, forms.Select) else 'form-control'
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.update({'class': 'form-check-input'})
            else:
                field.widget.attrs.update({'class': css})

    def clean(self):
        cleaned = super().clean()
        resource = cleaned.get('cloud_resource_id')
        if resource:
            cleaned['provider'] = resource.provider
            cleaned['resource_name'] = cleaned.get('resource_name') or resource.resource_name
            cleaned['resource_type'] = cleaned.get('resource_type') or resource.resource_type
            cleaned['region'] = cleaned.get('region') or resource.region
            cleaned['backend_ip'] = cleaned.get('backend_ip') or resource.private_ip
        payload = self.to_policy_payload(cleaned)
        try:
            self.normalized_policy = validate_policy(payload)
        except PolicyValidationError as exc:
            raise forms.ValidationError(str(exc)) from exc
        return cleaned

    def to_policy_payload(self, cleaned=None):
        data = cleaned or self.cleaned_data
        payload = {key: value for key, value in data.items() if key != 'cloud_resource_id'}
        if data.get('policy_type') == 'inbound_publish':
            payload['cloud_resource'] = {
                'provider': data.get('provider') or 'other',
                'resource_type': data.get('resource_type') or '',
                'name': data.get('resource_name') or '',
                'private_ip': str(data.get('backend_ip') or ''),
                'public_ip': None,
                'region': data.get('region') or '',
                'logo': data.get('provider') or 'other',
            }
        return payload
