from django import forms

from assets.models import Asset


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = ['name', 'asset_type', 'value', 'description', 'criticality', 'tags', 'status']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            if isinstance(field, forms.ChoiceField):
                field.widget.attrs.update({'class': 'form-select'})
            else:
                field.widget.attrs.update({'class': 'form-control'})
        self.fields['tags'].widget.attrs.update({'placeholder': 'production,critical,internet-facing'})

    def clean_value(self):
        return (self.cleaned_data.get('value') or '').strip()

    def clean(self):
        cleaned = super().clean()
        # Delegate validation to model clean so IP/domain/URL/CIDR checks stay centralized.
        if self.instance:
            for field_name, value in cleaned.items():
                setattr(self.instance, field_name, value)
            self.instance.clean()
        return cleaned
