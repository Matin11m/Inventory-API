from odoo.tests import TransactionCase
import json


class TestFilterPagination(TransactionCase):
    test_tags = ['filter', 'pagination']

    def setUp(self):
        super(TestFilterPagination, self).setUp()
        self.api_url = '/api/products'

    def test_filter_param(self):
        data = {
            'filter': '{"name": ["=", "Product A"]}'
        }
        response = self.env['ir.http'].send_request(self.api_url, data)
        response_json = json.loads(response.data)
        self.assertTrue(len(response_json['data']) > 0)

    def test_pagination(self):
        data = {
            'limit': 10,
            'offset': 0
        }
        response = self.env['ir.http'].send_request(self.api_url, data)
        response_json = json.loads(response.data)
        self.assertEqual(len(response_json['data']), 10)
