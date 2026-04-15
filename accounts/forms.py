from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import Organization, OrganizationMembership

User = get_user_model()


class EnterpriseAuthFormMixin:
    field_css_class = 'auth-input'

    def _apply_enterprise_styles(self):
        for name, field in self.fields.items():
            classes = field.widget.attrs.get('class', '')
            field.widget.attrs['class'] = f"{classes} {self.field_css_class}".strip()
            field.widget.attrs.setdefault('autocomplete', name)


class EmailAuthenticationForm(EnterpriseAuthFormMixin, AuthenticationForm):
    username = forms.EmailField(
        label='Email corporativo',
        widget=forms.EmailInput(
            attrs={
                'placeholder': 'security@empresa.com',
                'autocomplete': 'email',
            }
        ),
    )
    password = forms.CharField(
        label='Contraseña',
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                'placeholder': '••••••••',
                'autocomplete': 'current-password',
            }
        ),
    )
    remember_me = forms.BooleanField(label='Recordarme en este dispositivo', required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._apply_enterprise_styles()
        self.fields['remember_me'].widget.attrs['class'] = 'form-check-input'


class RegistrationForm(EnterpriseAuthFormMixin, forms.Form):
    first_name = forms.CharField(label='Nombre', max_length=150)
    last_name = forms.CharField(label='Apellido', max_length=150)
    email = forms.EmailField(label='Email corporativo')
    organization_name = forms.CharField(label='Organización', max_length=120)
    password1 = forms.CharField(
        label='Contraseña',
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text='Usa al menos 8 caracteres, combinando letras, números y símbolos.',
    )
    password2 = forms.CharField(
        label='Confirmar contraseña',
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._apply_enterprise_styles()

    def clean_email(self):
        email = self.cleaned_data['email'].lower().strip()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError('Ya existe una cuenta con ese email.')
        return email

    def clean_password1(self):
        password = self.cleaned_data['password1']
        try:
            validate_password(password)
        except ValidationError as exc:
            raise forms.ValidationError(exc.messages)
        return password

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('password1') and cleaned.get('password2') and cleaned.get('password1') != cleaned.get('password2'):
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
