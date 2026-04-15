import json
from pathlib import Path

from django.core.management.base import BaseCommand
from django.db import transaction

from accounts.models import Organization
from knowledge_base.models import (
    EndOfLifeRule,
    MisconfigurationRule,
    Product,
    ProductAlias,
    ReferenceLink,
    RemediationTemplate,
    VulnerabilityRule,
)
from scan_profiles.models import ScanProfile


class Command(BaseCommand):
    help = 'Carga datos semilla iniciales para VulnSight.'

    def handle(self, *args, **options):
        self._seed_scan_profiles()
        self._seed_knowledge_base()
        self.stdout.write(self.style.SUCCESS('Semillas cargadas correctamente.'))

    def _seed_scan_profiles(self):
        profiles = [
            ('discovery', 'Descubrimiento inicial seguro de host/servicios'),
            ('full_tcp_safe', 'Escaneo TCP defensivo sobre top 1000 puertos con detección de versiones'),
            ('web_basic', 'Orquesta fingerprinting web básico en puertos HTTP/HTTPS'),
            ('wordpress', 'Prepara orquestación WordPress cuando se detecta tecnología'),
            ('misconfiguration', 'Escaneo orientado a señales de mala configuración'),
        ]
        for org in Organization.objects.all():
            for name, description in profiles:
                ScanProfile.objects.update_or_create(
                    organization=org,
                    name=name,
                    defaults=self._scan_profile_defaults(name, description),
                )

    @transaction.atomic
    def _seed_knowledge_base(self):
        seed_dir = Path(__file__).resolve().parents[3] / 'knowledge_base' / 'seed_data'

        products_map = {}
        for item in self._load(seed_dir / 'products.json'):
            product, _ = Product.objects.update_or_create(
                name=item['name'],
                defaults={'vendor': item.get('vendor', '')},
            )
            products_map[product.name] = product

        remediations_map = {}
        for item in self._load(seed_dir / 'remediations.json'):
            remediation, _ = RemediationTemplate.objects.update_or_create(
                title=item['title'],
                defaults={'body': item['body']},
            )
            remediations_map[remediation.title] = remediation

        for item in self._load(seed_dir / 'aliases.json'):
            product = products_map[item['product']]
            ProductAlias.objects.update_or_create(alias=item['alias'], defaults={'product': product})

        vuln_rules = self._seed_rules(
            self._load(seed_dir / 'vulnerability_rules.json'),
            VulnerabilityRule,
            products_map,
            remediations_map,
        )
        misconf_rules = self._seed_rules(
            self._load(seed_dir / 'misconfiguration_rules.json'),
            MisconfigurationRule,
            products_map,
            remediations_map,
        )
        eol_rules = self._seed_rules(
            self._load(seed_dir / 'eol_rules.json'),
            EndOfLifeRule,
            products_map,
            remediations_map,
        )
        self._seed_rules(
            self._load(seed_dir / 'exposure_rules.json'),
            MisconfigurationRule,
            products_map,
            remediations_map,
        )

        self._seed_references(
            self._load(seed_dir / 'references.json'),
            vuln_rules,
            misconf_rules,
            eol_rules,
        )

    def _seed_rules(self, records, model_cls, products_map, remediations_map):
        rules = {}
        for item in records:
            product = products_map[item['product']]
            remediation = remediations_map.get(item.get('remediation'))
            defaults = {
                'description': item['description'],
                'severity': item.get('severity', 'medium'),
                'confidence': item.get('confidence', 'medium'),
                'cvss': item.get('cvss', 0.0),
                'min_version': item.get('min_version', ''),
                'max_version': item.get('max_version', ''),
                'version_operator': item.get('version_operator', ''),
                'version_value': item.get('version_value', ''),
                'service_name': item.get('service_name', ''),
                'port': item.get('port'),
                'protocol': item.get('protocol', ''),
                'required_state': item.get('required_state', ''),
                'evidence_type': item.get('evidence_type', ''),
                'required_evidence': item.get('required_evidence', ''),
                'remediation_template': remediation,
            }
            if model_cls is VulnerabilityRule:
                defaults['cve'] = item.get('cve', '')
            if model_cls is EndOfLifeRule:
                defaults['eol_date'] = item.get('eol_date')

            rule, _ = model_cls.objects.update_or_create(
                title=item['title'],
                product=product,
                defaults=defaults,
            )
            rules[rule.title] = rule
        return rules

    def _seed_references(self, records, vuln_rules, misconf_rules, eol_rules):
        for item in records:
            rule_type = item['rule_type']
            title = item['rule_title']
            if rule_type == 'vulnerability':
                kwargs = {'vulnerability_rule': vuln_rules[title]}
            elif rule_type == 'misconfiguration':
                kwargs = {'misconfiguration_rule': misconf_rules[title]}
            elif rule_type == 'eol':
                kwargs = {'end_of_life_rule': eol_rules[title]}
            else:
                raise ValueError(f"Tipo de regla no soportado: {rule_type}")

            ReferenceLink.objects.update_or_create(
                url=item['url'],
                defaults={'label': item['label'], **kwargs},
            )

    def _load(self, filepath: Path):
        with filepath.open('r', encoding='utf-8') as f:
            return json.load(f)

    def _scan_profile_defaults(self, name, description):
        return {
            'description': description,
            'host_discovery': True,
            'port_detection': True,
            'version_detection': True,
            'web_detection': name in {'web_basic', 'wordpress', 'misconfiguration'},
            'light_enumeration': name in {'full_tcp_safe', 'misconfiguration'},
            'wordpress_scan': name == 'wordpress',
        }
