from odoo.tests.common import TransactionCase
from ..utils.cache import invalidate_cache


class TestCache(TransactionCase):
    test_tags = ['cache', 'test']

    def setUp(self):
        super(TestCache, self).setUp()
        self.api_url = '/api/products'

    def test_cache_invalidation(self):
        product = self.env['product.template'].create({
            'name': 'Test Product',
            'list_price': 100
        })

        response1 = self.env['ir.http'].send_request(self.api_url)
        cached_data = response1.data

        product.write({'list_price': 150})
        invalidate_cache(f"product_data_{product.id}")

        response2 = self.env['ir.http'].send_request(self.api_url)

        self.assertNotEqual(response2.data, cached_data)
