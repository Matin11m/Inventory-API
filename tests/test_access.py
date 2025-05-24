from odoo.tests import TransactionCase


class TestAuthorization(TransactionCase):
    test_tags = ['test', 'authorization']

    def setUp(self):
        super(TestAuthorization, self).setUp()
        self.api_url = '/api/stock'

    def test_authorized_access(self):
        response = self.env['ir.http'].send_request(self.api_url)
        self.assertEqual(response.status_code, 200)

    def test_unauthorized_access(self):
        response = self.env['ir.http'].send_request(self.api_url)
        self.assertEqual(response.status_code, 403)
