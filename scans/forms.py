from django import forms

from scan_profiles.models import ScanProfile


class CreateScanForm(forms.Form):
    profile = forms.ModelChoiceField(queryset=ScanProfile.objects.none(), label='Scan profile')

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization:
            self.fields['profile'].queryset = ScanProfile.objects.filter(organization=organization).order_by('name')
            self.fields['profile'].empty_label = 'Selecciona un perfil'
            self.fields['profile'].widget.attrs.update({'class': 'form-select'})
