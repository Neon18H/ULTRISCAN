from django.test import TestCase

from assets.models import Asset


class ModelTests(TestCase):
    def test_str(self):
        asset = Asset.objects.create(name='Srv', asset_type='domain', value='example.com')
        self.assertIn('example.com', str(asset))
