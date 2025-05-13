from odoo.tests.common import TransactionCase
from datetime import datetime


class TestApiLog(TransactionCase):
    test_tags = ['model', 'test']

    def setUp(self):
        super(TestApiLog, self).setUp()
        self.api_log_model = self.env['api.log']

    def test_api_log_creation(self):
        user = self.env['res.users'].create({
            'name': 'Test User',
            'login': 'testuser',
            'password': 'password123',
        })

        log_data = {
            'user_id': user.id,
            'path': '/api/products',
            'ip_address': '127.0.0.1',
            'method': 'GET',
            'params': '{}',
            'status_code': 200,
            'timestamp': datetime.now(),
            'response_time': 123
        }

        log = self.api_log_model.create(log_data)

        self.assertTrue(log.id)
        self.assertEqual(log.path, '/api/products')
        self.assertEqual(log.status_code, 200)

    def test_api_log_access(self):
        user = self.env['res.users'].create({
            'name': 'Admin User',
            'login': 'adminuser',
            'password': 'admin123',
        })

        api_log = self.env['api.log'].create({
            'user_id': user.id,
            'path': '/api/products',
            'status_code': 200
        })

        self.assertEqual(api_log.user_id.name, 'Admin User')
        self.assertEqual(api_log.status_code, 200)
