from odoo.tests import TransactionCase


class TestRateLimit(TransactionCase):
    test_tags = ['rate_limit', 'test']

    def setUp(self):
        super(TestRateLimit, self).setUp()
        self.api_url = '/api/products'

    def test_rate_limiting(self):
        for _ in range(15):
            response = self.env['ir.http'].send_request(self.api_url)

        response = self.env['ir.http'].send_request(self.api_url)
        self.assertEqual(response.status_code, 429)
