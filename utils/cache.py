from odoo.http import request
from odoo.tools import cache
import logging

_logger = logging.getLogger(__name__)

def invalidate_cache(key):
    _logger.info("Invalidating cache for key: %s", key)
    request.env.cache.invalidate([key])

def update_stock_quant_data(product_id):
    request.env['stock.quant'].sudo().search([('product_id', '=', product_id)]).write({'quantity': new_quantity})

    invalidate_cache(f"stock_quant_data_{product_id}")
