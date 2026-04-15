from django.core.management import call_command
from django.test import TestCase

from knowledge_base.models import EndOfLifeRule, MisconfigurationRule, Product, ProductAlias, RemediationTemplate, VulnerabilityRule


class SeedInitialDataTests(TestCase):
    def test_seed_initial_data_is_idempotent(self):
        call_command('seed_initial_data')
        counts_first = {
            'products': Product.objects.count(),
            'aliases': ProductAlias.objects.count(),
            'remediations': RemediationTemplate.objects.count(),
            'vuln': VulnerabilityRule.objects.count(),
            'misconf': MisconfigurationRule.objects.count(),
            'eol': EndOfLifeRule.objects.count(),
        }

        call_command('seed_initial_data')
        counts_second = {
            'products': Product.objects.count(),
            'aliases': ProductAlias.objects.count(),
            'remediations': RemediationTemplate.objects.count(),
            'vuln': VulnerabilityRule.objects.count(),
            'misconf': MisconfigurationRule.objects.count(),
            'eol': EndOfLifeRule.objects.count(),
        }

        self.assertEqual(counts_first, counts_second)
        self.assertGreaterEqual(counts_second['products'], 14)
        self.assertGreaterEqual(counts_second['vuln'], 6)
        self.assertGreaterEqual(counts_second['misconf'], 20)
        self.assertGreaterEqual(counts_second['eol'], 4)
