import re


def validate_username(username):
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        raise ValueError("Username can only contain letters, numbers, and underscores.")
    return username


def validate_password(password):
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
