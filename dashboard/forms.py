from django import forms

from scan_profiles.models import ScanProfile


class LaunchScanForm(forms.Form):
    profile = forms.ModelChoiceField(queryset=ScanProfile.objects.none(), label='Perfil de escaneo')

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization:
            self.fields['profile'].queryset = ScanProfile.objects.filter(organization=organization).order_by('name')
