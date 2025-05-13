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
