from ..utils import config


def get_stock_location(env):
    stock_location = env['stock.location'].search([
        ('usage', '=', 'internal'),
        ('name', '=', config.DEFAULT_STOCK_LOCATION)
    ], limit=1)
    if not stock_location:
        raise ValueError(f"Default stock location ({config.DEFAULT_STOCK_LOCATION}) not found")
    return stock_location


def check_duplicates(env, products):
    unique_products = []
    skipped_products = []

    product_keys = [(p.get('default_code'), p.get('name')) for p in products]
    default_codes = [key[0] for key in product_keys if key[0]]
    names = [key[1] for key in product_keys if key[1]]

    existing_products = env['product.product'].search([
        ('default_code', 'in', default_codes),
        ('name', 'in', names)
    ])
    existing_map = {(p.default_code, p.name): p for p in existing_products}

    for product_data in products:
        default_code = product_data.get('default_code')
        name = product_data.get('name')
        if not default_code or not name:
            skipped_products.append(product_data)
            continue

        if (default_code, name) in existing_map:
            skipped_products.append(product_data)
        else:
            unique_products.append(product_data)

    return unique_products, skipped_products


def create_products_and_quants(env, products_data, stock_location):
    created_products = []
    quant_vals = []
    for product_data in products_data:
        product = env['product.product'].create(product_data)
        created_products.append(product.id)
        quant_vals.append({
            'product_id': product.id,
            'location_id': stock_location.id,
            'quantity': 0
        })

    if quant_vals:
        env['stock.quant'].create(quant_vals)

    return created_products
