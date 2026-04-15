from django.core.exceptions import ValidationError
from django.test import TestCase

from assets.models import Asset


class AssetValidationTests(TestCase):
    def test_invalid_ip_raises(self):
        asset = Asset(name='A', asset_type='ip', value='999.999.1.1')
        with self.assertRaises(ValidationError):
            asset.full_clean()
