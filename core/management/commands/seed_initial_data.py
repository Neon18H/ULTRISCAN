from django.core.management.base import BaseCommand

from knowledge_base.models import Product, RemediationTemplate, VulnerabilityRule
from scan_profiles.models import ScanProfile


class Command(BaseCommand):
    help = 'Carga datos semilla iniciales para vulnsight.'

    def handle(self, *args, **options):
        for profile in [('Básico', True, True, False, False, False, False), ('Estándar', True, True, True, True, True, False), ('Web', True, True, True, True, True, False), ('WordPress', True, True, True, True, True, True)]:
            ScanProfile.objects.get_or_create(
                name=profile[0],
                defaults={'host_discovery': profile[1], 'port_detection': profile[2], 'version_detection': profile[3], 'web_detection': profile[4], 'light_enumeration': profile[5], 'wordpress_scan': profile[6]},
            )
        remediation, _ = RemediationTemplate.objects.get_or_create(title='Actualización de servicio', defaults={'body': 'Actualizar a versión soportada y reforzar configuración.'})
        for name in ['OpenSSH', 'Apache HTTP Server', 'nginx', 'WordPress']:
            Product.objects.get_or_create(name=name)
        openssh = Product.objects.get(name='OpenSSH')
        VulnerabilityRule.objects.get_or_create(
            title='OpenSSH desactualizado', product=openssh,
            defaults={'severity': 'medium', 'confidence': 'high', 'cvss': 6.5, 'description': 'Servicio OpenSSH en rama antigua con potenciales riesgos.', 'min_version': '1.0', 'max_version': '8.8', 'port': 22, 'protocol': 'tcp', 'remediation_template': remediation},
        )
        self.stdout.write(self.style.SUCCESS('Semillas cargadas correctamente.'))
