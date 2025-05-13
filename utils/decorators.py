from functools import wraps

from odoo.http import request


def require_group(xml_id):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if xml_id not in getattr(request, 'jwt_groups', []):
                return request.make_json_response({'error': 'Permission denied'}, status=403)
            return f(*args, **kwargs)

        return wrapper

    return decorator
