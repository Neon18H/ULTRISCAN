from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class LogoutFlowTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username='tester',
            email='tester@example.com',
            password='secret1234',
        )

    def test_logout_requires_post_and_redirects_to_login(self):
        self.client.force_login(self.user)

        response = self.client.post(reverse('logout'))

        self.assertRedirects(response, reverse('login'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_topbar_uses_post_logout_form_with_csrf(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse('dashboard-home'))

        self.assertContains(response, f'action="{reverse("logout")}"')
        self.assertContains(response, 'method="post"', html=False)
        self.assertContains(response, 'csrfmiddlewaretoken', html=False)
