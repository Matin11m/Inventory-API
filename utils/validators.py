import re
from ..utils import config


def validate_username(username):
    if not username or not isinstance(username, str):
        raise ValueError("Username is required and must be a string.")
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        raise ValueError("Username can only contain letters, numbers, and underscores.")
    return username


def validate_password(password):
    if not password or not isinstance(password, str):
        raise ValueError("Password is required and must be a string.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', password):
        raise ValueError("Password must contain at least one number.")
    return password


def validate_limit_offset(kwargs):
    limit = kwargs.get('limit', 50)
    offset = kwargs.get('offset', 0)

    if not isinstance(limit, int) or limit <= 0:
        raise ValueError("Limit must be a positive integer.")

    if not isinstance(offset, int) or offset < 0:
        raise ValueError("Offset must be a non-negative integer.")

    return limit, offset


def extract_valid_fields(fields_param, model_fields, default_fields):
    if not fields_param:
        return default_fields

    fields = fields_param.split(',')

    for field in fields:
        if field not in model_fields:
            raise ValueError(f"Field '{field}' is not valid.")

    return fields


# def validate_json_input(data, max_items=config.MAX_PRODUCTS):
#     if not isinstance(data, list):
#         raise ValueError("Input must be a list of products")
#     if len(data) > max_items:
#         raise ValueError(f"Maximum {max_items} products allowed per request")
#     if not data:
#         raise ValueError("Product list cannot be empty")
#
#
# def validate_product_data(product_data, allowed_fields, product_index=None):
#     error_prefix = f"Product at index {product_index}" if product_index is not None else "Product"
#
#     if not product_data.get('name'):
#         raise ValueError(f"{error_prefix}: Name is required")
#
#     if product_data.get('type') not in ['product', 'consu', 'service']:
#         product_data['type'] = 'product'
#
#     if 'list_price' in product_data and product_data['list_price'] < 0:
#         raise ValueError(f"{error_prefix}: List price cannot be negative")
#
#     dangerous_chars = re.compile(r'[<>&]')
#     for key, value in product_data.items():
#         if key in allowed_fields and isinstance(value, str):
#             if dangerous_chars.search(value):
#                 raise ValueError(f"{error_prefix}: Invalid characters in {key}")
#
#     return {k: v for k, v in product_data.items() if k in allowed_fields}


def validate_json_input(data, max_items=config.MAX_PRODUCTS):
    if not isinstance(data, list):
        raise ValueError("Input must be a list of products")
    if len(data) > max_items:
        raise ValueError(f"Maximum {max_items} products allowed per request")
    if not data:
        raise ValueError("Product list cannot be empty")


def validate_product_data(product_data, allowed_fields, product_index=None):
    error_prefix = f"Product at index {product_index}" if product_index is not None else "Product"

    if not product_data.get('name'):
        raise ValueError(f"{error_prefix}: Name is required")

    if product_data.get('type') not in ['product', 'consu', 'service']:
        product_data['type'] = 'product'

    if 'list_price' in product_data and product_data['list_price'] < 0:
        raise ValueError(f"{error_prefix}: List price cannot be negative")

    # چک کردن کاراکترهای خطرناک توی همه فیلدهای رشته‌ای
    dangerous_chars = re.compile(r'[<>&]')
    for key, value in product_data.items():
        if key in allowed_fields and isinstance(value, str):
            if dangerous_chars.search(value):
                raise ValueError(f"{error_prefix}: Invalid characters in {key}")

    return {k: v for k, v in product_data.items() if k in allowed_fields}


def validate_image_file(file):
    if not file or not hasattr(file, 'filename'):
        return False
    allowed_types = ['image/jpeg', 'image/png', 'image/gif']
    if file.content_type not in allowed_types:
        raise ValueError(f"Unsupported image type. Allowed types are {', '.join(allowed_types)}")
    if file.content_length > 5 * 1024 * 1024:  # حداکثر 5MB
        raise ValueError("Image size exceeds 5MB limit")
    return True
