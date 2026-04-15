from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from scan_profiles.models import ScanProfile


class ScanIsolationTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user1 = user_model.objects.create_user(username='u1', email='u1@example.com', password='test12345')
        self.user2 = user_model.objects.create_user(username='u2', email='u2@example.com', password='test12345')
        self.org1 = Organization.objects.create(name='Org1', slug='org1')
        self.org2 = Organization.objects.create(name='Org2', slug='org2')
        OrganizationMembership.objects.create(user=self.user1, organization=self.org1, role='owner', is_active=True)
        OrganizationMembership.objects.create(user=self.user2, organization=self.org2, role='owner', is_active=True)

        self.asset2 = Asset.objects.create(organization=self.org2, name='Srv2', asset_type='ip', value='10.0.0.22')
        self.profile1 = ScanProfile.objects.create(organization=self.org1, name='discovery')

    def test_user_cannot_create_scan_for_other_org_asset(self):
        client = APIClient()
        client.force_authenticate(user=self.user1)
        response = client.post('/api/scans/', {'asset': self.asset2.id, 'profile': self.profile1.id})
        self.assertEqual(response.status_code, 403)
