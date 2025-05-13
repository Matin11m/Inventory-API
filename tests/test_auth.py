import json
from odoo.tests.common import TransactionCase


class TestAuth(TransactionCase):
    test_tags = ['auth', 'login']

    def setUp(self):
        super(TestAuth, self).setUp()
        self.api_url = '/api/login'
        self.test_user = self.env['res.users'].create({
            'name': 'Test User',
            'login': 'admin',
            'password': 'admin',
        })

    def test_login_valid(self):
        data = {
            'username': 'admin',
            'password': 'admin'
        }
        response = self.env['ir.http'].send_request(self.api_url, data)
        response_json = json.loads(response.data)
        self.assertTrue('token' in response_json)

    def test_login_invalid(self):
        data = {
            'username': 'wronguser',
            'password': 'wrongpassword'
        }
        response = self.env['ir.http'].send_request(self.api_url, data)
        response_json = json.loads(response.data)
        self.assertEqual(response.status_code, 401)
        self.assertTrue('error' in response_json)
