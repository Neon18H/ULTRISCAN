from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm

from .models import Organization, OrganizationMembership

User = get_user_model()


class EmailAuthenticationForm(AuthenticationForm):
    username = forms.EmailField(label='Email', widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'tu@empresa.com'}))
    password = forms.CharField(label='Contraseña', strip=False, widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': '••••••••'}))


class RegistrationForm(forms.Form):
    first_name = forms.CharField(label='Nombre', max_length=150)
    last_name = forms.CharField(label='Apellido', max_length=150)
    email = forms.EmailField(label='Email')
    password1 = forms.CharField(label='Contraseña', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirmar contraseña', widget=forms.PasswordInput)
    organization_name = forms.CharField(label='Organización', max_length=120)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

    def clean_email(self):
        email = self.cleaned_data['email'].lower().strip()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError('Ya existe una cuenta con ese email.')
        return email

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('password1') != cleaned.get('password2'):
            self.add_error('password2', 'Las contraseñas no coinciden.')
        return cleaned

    def save(self):
        organization = Organization.objects.create(name=self.cleaned_data['organization_name'])
        user = User.objects.create_user(
            username=self.cleaned_data['email'],
            email=self.cleaned_data['email'],
            password=self.cleaned_data['password1'],
            first_name=self.cleaned_data['first_name'],
            last_name=self.cleaned_data['last_name'],
        )
        OrganizationMembership.objects.create(
            user=user,
            organization=organization,
            role=OrganizationMembership.Role.OWNER,
        )
        return user


class MembershipRoleForm(forms.ModelForm):
    class Meta:
        model = OrganizationMembership
        fields = ['role']
        widgets = {'role': forms.Select(attrs={'class': 'form-select'})}


class TeamMemberCreateForm(forms.Form):
    first_name = forms.CharField(label='Nombre', max_length=150)
    last_name = forms.CharField(label='Apellido', max_length=150, required=False)
    email = forms.EmailField(label='Email')
    role = forms.ChoiceField(choices=OrganizationMembership.Role.choices)

    def __init__(self, *args, **kwargs):
        self.organization = kwargs.pop('organization')
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-select' if name == 'role' else 'form-control'

    def save(self):
        email = self.cleaned_data['email'].lower().strip()
        user, _ = User.objects.get_or_create(
            email=email,
            defaults={
                'username': email,
                'first_name': self.cleaned_data['first_name'],
                'last_name': self.cleaned_data['last_name'],
            },
        )
        membership, _ = OrganizationMembership.objects.get_or_create(
            user=user,
            organization=self.organization,
            defaults={'role': self.cleaned_data['role']},
        )
        if membership.role != self.cleaned_data['role']:
            membership.role = self.cleaned_data['role']
            membership.save(update_fields=['role'])
        return membership
