import re

from odoo.exceptions import ValidationError
from ..utils import config
from datetime import datetime

ALLOWED_CUSTOMER_FIELDS = ['name', 'email', 'phone', 'street']
REQUIRED_FIELDS = ['name']
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PHONE_REGEX = r'^[0-9+\-]+$'
MAX_LENGTH = 128


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
    if file.content_length > 5 * 1024 * 1024:
        raise ValueError("Image size exceeds 5MB limit")
    return True


def validate_date(date_str, field_name):
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        raise ValidationError(f"{field_name} must be in YYYY-MM-DD format")


def validate_invoice_data(data):
    required_fields = ['customer_id', 'invoice_date', 'invoice_lines']
    for field in required_fields:
        if field not in data or not data[field]:
            raise ValidationError(f"{field} is required")

    customer_id = data.get('customer_id')
    if not isinstance(customer_id, int):
        raise ValidationError("Customer ID must be an integer")

    invoice_date = data.get('invoice_date')
    validate_date(invoice_date, "Invoice date")

    due_date = data.get('due_date')
    if due_date:
        validate_date(due_date, "Due date")

    invoice_lines = data.get('invoice_lines')
    if not isinstance(invoice_lines, list) or len(invoice_lines) == 0:
        raise ValidationError("Invoice lines must be a non-empty list")

    if len(invoice_lines) > config.MAX_INVOICE_LINES:
        raise ValidationError(f"Too many invoice lines. Maximum allowed is {config.MAX_INVOICE_LINES}")

    return {
        'customer_id': customer_id,
        'invoice_date': invoice_date,
        'due_date': due_date,
        'post_immediately': data.get('post_immediately', False),
        'invoice_lines': invoice_lines
    }


def validate_invoice_line(line, idx):
    required_fields = ['product_id', 'quantity', 'price_unit']
    for field in required_fields:
        if field not in line or line[field] is None:
            raise ValidationError(f"Line {idx}: {field} is required")

    product_id = line.get('product_id')
    if not isinstance(product_id, int):
        raise ValidationError(f"Line {idx}: Product ID must be an integer")

    quantity = line.get('quantity')
    if not isinstance(quantity, (int, float)) or quantity <= 0 or quantity > 1000:
        raise ValidationError(f"Line {idx}: Quantity must be a positive number and not exceed 1000")

    price_unit = line.get('price_unit')
    if not isinstance(price_unit, (int, float)) or price_unit < 0 or price_unit > 1000000:
        raise ValidationError(f"Line {idx}: Price unit must be a non-negative number and not exceed 1000000")

    tax_ids = line.get('tax_ids', [])
    if not isinstance(tax_ids, list):
        raise ValidationError(f"Line {idx}: tax_ids must be a list")

    return {
        'product_id': product_id,
        'quantity': quantity,
        'price_unit': price_unit,
        'description': line.get('description', False),
        'tax_ids': tax_ids
    }


def validate_location_id(params):
    if 'location_id' not in params:
        return None
    try:
        return int(params['location_id'])
    except ValueError:
        raise ValueError("location_id must be an integer")


def validate_customer_data(data):
    if not isinstance(data, dict):
        raise ValueError("Customer data must be a JSON object")

    validated_data = {}
    for field in REQUIRED_FIELDS:
        if field not in data or not data[field]:
            raise ValueError(f"Missing or empty required field: {field}")

    for field, value in data.items():
        if field not in ALLOWED_CUSTOMER_FIELDS:
            raise ValueError(f"Field not allowed: {field}")
        if value:
            if not isinstance(value, str):
                raise ValueError(f"Invalid type for field {field}: must be string")
            if len(value) > MAX_LENGTH:
                raise ValueError(f"Field {field} exceeds maximum length of {MAX_LENGTH} characters")
            if field == 'email' and not re.match(EMAIL_REGEX, value):
                raise ValueError("Invalid email format")
            if field == 'phone' and not re.match(PHONE_REGEX, value):
                raise ValueError("Invalid phone format")
            validated_data[field] = value
        else:
            validated_data[field] = False

    validated_data['customer_rank'] = 1
    return validated_data


def validate_limit_offset2(params):
    try:
        limit = int(params.get('limit', 100))
        offset = int(params.get('offset', 0))
    except (TypeError, ValueError):
        raise ValueError("Limit and offset must be valid integers")
    if limit <= 0:
        raise ValueError("Limit must be a positive integer")
    if offset < 0:
        raise ValueError("Offset must be a non-negative integer")
    if limit > 1000:
        raise ValueError("Limit cannot exceed 1000")
    return limit, offset
