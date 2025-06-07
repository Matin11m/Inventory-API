import logging

from odoo.http import request

_logger = logging.getLogger(__name__)

ALLOWED_CUSTOMER_FIELDS = ['name', 'email', 'phone', 'street']


def build_product_domain(params):
    domain = [('qty_available', '>', 0)]

    if 'name' in params:
        domain.append(('name', 'ilike', params['name']))
    if 'default_code' in params:
        domain.append(('default_code', 'ilike', params['default_code']))
    if 'min_price' in params:
        try:
            domain.append(('list_price', '>=', float(params['min_price'])))
        except ValueError:
            pass
    if 'max_price' in params:
        try:
            domain.append(('list_price', '<=', float(params['max_price'])))
        except ValueError:
            pass
    if 'category_ids' in params:
        try:
            ids = [int(i) for i in params['category_ids'].split(',') if i.strip().isdigit()]
            domain.append(('categ_id', 'in', ids))
        except Exception:
            pass
    if 'category' in params:
        domain.append(('categ_id.name', '=', params['category']))

    return domain


def build_stock_domain(params):
    domain = []
    location_id = params.get('location_id')
    if location_id:
        try:
            domain.append(('location_id', '=', int(location_id)))
        except ValueError:
            pass
    return domain


def build_customer_domain(params):
    domain = [('customer_rank', '>', 0)]
    for field, value in params.items():
        if field not in ALLOWED_CUSTOMER_FIELDS:
            raise ValueError(f"Field not allowed: {field}")
        if value:
            if field in ['name', 'email', 'street']:
                domain.append((field, 'ilike', value))
            elif field == 'phone':
                domain.append((field, '=', value))
    return domain


def get_customer_count(domain):
    return request.env['res.partner'].with_user(request.env.user).search_count(domain)


def get_customer_by_id(customer_id, fields):
    if not request.env['res.partner'].with_user(request.env.user).search([('id', '=', customer_id)], limit=1):
        return []

    return request.env['res.partner'].with_user(request.env.user).search_read(
        domain=[('id', '=', customer_id)],
        fields=fields,
        limit=1
    )
