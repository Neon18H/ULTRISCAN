from django.core.management.base import BaseCommand

from accounts.models import Organization
from knowledge_base.models import EndOfLifeRule, MisconfigurationRule, Product, ProductAlias, ReferenceLink, RemediationTemplate, VulnerabilityRule
from scan_profiles.models import ScanProfile


class Command(BaseCommand):
    help = 'Carga datos semilla iniciales para vulnsight.'

    def handle(self, *args, **options):
        self._seed_scan_profiles()
        self._seed_knowledge_base()
        self.stdout.write(self.style.SUCCESS('Semillas cargadas correctamente.'))

    def _seed_scan_profiles(self):
        profiles = [
            ('discovery', 'Descubrimiento inicial seguro de host/servicios'),
            ('full_tcp_safe', 'Escaneo TCP completo defensivo con detección de versiones'),
            ('web_basic', 'Orquesta fingerprinting web básico en puertos HTTP/HTTPS'),
            ('wordpress', 'Prepara orquestación WordPress cuando se detecta tecnología'),
            ('misconfiguration', 'Escaneo orientado a señales de mala configuración'),
        ]
        for org in Organization.objects.all():
            for name, description in profiles:
                ScanProfile.objects.get_or_create(
                    organization=org,
                    name=name,
                    defaults={
                        'description': description,
                        'host_discovery': True,
                        'port_detection': True,
                        'version_detection': True,
                        'web_detection': name in {'web_basic', 'wordpress', 'misconfiguration'},
                        'light_enumeration': name in {'full_tcp_safe', 'misconfiguration'},
                        'wordpress_scan': name == 'wordpress',
                    },
                )

    def _seed_knowledge_base(self):
        update_remediation, _ = RemediationTemplate.objects.get_or_create(
            title='Actualización de servicio',
            defaults={'body': 'Actualizar a una versión soportada y volver a escanear para validar mitigación.'},
        )
        hardening_remediation, _ = RemediationTemplate.objects.get_or_create(
            title='Endurecimiento de configuración',
            defaults={'body': 'Aplicar configuración segura del servicio y restringir exposición de red.'},
        )

        products = {
            'OpenSSH': {'aliases': ['OpenSSH']},
            'Apache HTTP Server': {'aliases': ['Apache httpd', 'apache']},
            'nginx': {'aliases': ['nginx']},
            'WordPress': {'aliases': ['WordPress']},
            'PHP': {'aliases': ['php']},
            'FTP': {'aliases': ['ftp']},
            'Generic Web Panel': {'aliases': ['admin panel']},
        }

        for product_name, data in products.items():
            product, _ = Product.objects.get_or_create(name=product_name)
            for alias in data['aliases']:
                ProductAlias.objects.get_or_create(product=product, alias=alias)

        openssh = Product.objects.get(name='OpenSSH')
        apache = Product.objects.get(name='Apache HTTP Server')
        nginx = Product.objects.get(name='nginx')
        wordpress = Product.objects.get(name='WordPress')
        php = Product.objects.get(name='PHP')
        ftp = Product.objects.get(name='FTP')
        web_panel = Product.objects.get(name='Generic Web Panel')

        ssh_rule, _ = VulnerabilityRule.objects.get_or_create(
            title='OpenSSH potencialmente desactualizado',
            product=openssh,
            defaults={'severity': 'medium', 'confidence': 'high', 'cvss': 6.5, 'description': 'Versión de OpenSSH en rama antigua detectada.', 'min_version': '1.0', 'max_version': '8.8', 'port': 22, 'protocol': 'tcp', 'remediation_template': update_remediation},
        )
        apache_eol, _ = EndOfLifeRule.objects.get_or_create(
            title='Apache HTTP Server fuera de soporte',
            product=apache,
            defaults={'severity': 'high', 'confidence': 'medium', 'description': 'Se detecta versión de Apache en rango EOL.', 'min_version': '1.0', 'max_version': '2.3.99', 'port': 80, 'protocol': 'tcp', 'remediation_template': update_remediation},
        )
        VulnerabilityRule.objects.get_or_create(
            title='nginx con versión antigua',
            product=nginx,
            defaults={'severity': 'medium', 'confidence': 'medium', 'description': 'nginx en versión antigua con historial de vulnerabilidades.', 'min_version': '1.0', 'max_version': '1.18.0', 'port': 80, 'protocol': 'tcp', 'remediation_template': update_remediation},
        )
        EndOfLifeRule.objects.get_or_create(
            title='WordPress desactualizado',
            product=wordpress,
            defaults={'severity': 'high', 'confidence': 'medium', 'description': 'WordPress detectado en rama potencialmente desactualizada.', 'min_version': '1.0', 'max_version': '6.1.0', 'port': 80, 'protocol': 'tcp', 'remediation_template': update_remediation},
        )
        EndOfLifeRule.objects.get_or_create(
            title='PHP fuera de soporte',
            product=php,
            defaults={'severity': 'high', 'confidence': 'medium', 'description': 'Versión de PHP fuera de soporte activo.', 'min_version': '1.0', 'max_version': '7.4.99', 'protocol': 'tcp', 'remediation_template': update_remediation},
        )
        MisconfigurationRule.objects.get_or_create(
            title='Servicio FTP potencialmente permisivo',
            product=ftp,
            defaults={'severity': 'medium', 'confidence': 'low', 'description': 'Servicio FTP expuesto. Validar que no exista acceso anónimo.', 'port': 21, 'protocol': 'tcp', 'required_evidence': 'anonymous', 'remediation_template': hardening_remediation},
        )
        MisconfigurationRule.objects.get_or_create(
            title='Panel administrativo expuesto',
            product=web_panel,
            defaults={'severity': 'medium', 'confidence': 'low', 'description': 'Interfaz administrativa expuesta públicamente.', 'port': 80, 'protocol': 'tcp', 'required_evidence': 'admin', 'remediation_template': hardening_remediation},
        )
        MisconfigurationRule.objects.get_or_create(
            title='Headers de seguridad ausentes (preparada)',
            product=apache,
            defaults={'severity': 'low', 'confidence': 'low', 'description': 'Regla preparada para evidencias web de headers de seguridad.', 'required_evidence': 'missing-security-headers', 'remediation_template': hardening_remediation},
        )

        ReferenceLink.objects.get_or_create(vulnerability_rule=ssh_rule, label='OpenSSH', url='https://www.openssh.com/releasenotes.html')
        ReferenceLink.objects.get_or_create(end_of_life_rule=apache_eol, label='Apache HTTP Server', url='https://endoflife.date/apache-http-server')
