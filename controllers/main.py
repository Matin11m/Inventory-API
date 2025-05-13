import csv
import io
import json
import logging
from functools import wraps

from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from odoo import http
from odoo.http import request
from odoo.tools import cache
from ..utils.auth import create_jwt_token, decode_jwt_token
from ..utils.cache import invalidate_cache
from ..utils.decorators import require_group
from ..utils.json_filter import parse_filter_param
from ..utils.json_filter import parse_stock_filter_param
from ..utils.logging import log_error
from ..utils.query import build_product_domain
from ..utils.query import build_stock_domain
from ..utils.rate_limit import RateLimiter
from ..utils.rate_limit import rate_limited
from ..utils.validators import validate_limit_offset, extract_valid_fields, validate_username, validate_password

_logger = logging.getLogger(__name__)
rate_limiter = RateLimiter()


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.httprequest.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return http.Response(json.dumps({'error': 'Authentication required'}), status=401,
                                 content_type='application/json')

        try:
            token = auth_header.split(' ')[1]
            payload = decode_jwt_token(token)
            user_id = payload.get('user_id')
            request.jwt_groups = payload.get('groups', [])
            if not user_id:
                return http.Response(json.dumps({'error': 'Invalid token'}), status=401,
                                     content_type='application/json')

            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists():
                return http.Response(json.dumps({'error': 'User not found'}), status=404,
                                     content_type='application/json')

            request.env = request.env(user=user.id)

        except ExpiredSignatureError:
            return http.Response(json.dumps({'error': 'Token expired'}), status=401, content_type='application/json')
        except InvalidTokenError:
            return http.Response(json.dumps({'error': 'Invalid token'}), status=401, content_type='application/json')
        except Exception as e:
            _logger.error("Auth error: %s", str(e))
            return http.Response(json.dumps({'error': 'Unexpected error'}), status=500, content_type='application/json')

        return f(*args, **kwargs)

    return wrapper


class InventoryAuthController(http.Controller):

    @cache()
    def get_cached_stock(self, domain, fields, limit, offset):
        return request.env['stock.quant'].sudo().search_read(domain, fields, limit=limit, offset=offset)

    @cache()
    def get_stock_count(self, domain):
        return request.env['stock.quant'].sudo().search_count(domain)

    @cache()
    def get_product_count(self, domain):
        return request.env['product.template'].search_count(domain)

    @cache()
    def get_product_by_id_cached(self, product_id, fields):
        return request.env['product.template'].search_read(
            domain=[('id', '=', product_id), ('qty_available', '>', 0)],
            fields=fields,
            limit=1
        )

    @http.route('/api/login', type='http', auth='none', methods=['POST'], csrf=False)
    @rate_limited(rate_limiter, max_requests=3, time_window=60)
    def login(self, **kwargs):
        try:
            data = json.loads(request.httprequest.data.decode('utf-8'))
            username = data.get('username')
            password = data.get('password')

            validate_username(username)
            validate_password(password)

            if not username or not password:
                raise ValueError("Username and password required")

            user = request.env['res.users'].sudo().search([('login', '=', username)], limit=1)

            if not user.exists():
                raise ValueError("User not found")

            if not user.check_password(password):
                raise ValueError("Invalid password")

            token = create_jwt_token(user.id)
            return json.dumps({'token': token})

        except ValueError as e:

            log_error("Invalid credentials or missing parameters", e)
            return http.Response(json.dumps({'error': 'Invalid credentials'}), status=401,
                                 content_type='application/json')
        except Exception as e:

            log_error("Unexpected error during login", e)
            return http.Response(json.dumps({'error': 'Internal server error'}), status=500,
                                 content_type='application/json')

    @http.route('/api/products', type='http', auth='none', methods=['GET'], csrf=False)
    @rate_limited(rate_limiter, max_requests=5, time_window=60)
    @require_auth
    def get_products(self, **kwargs):
        try:

            limit, offset = validate_limit_offset(kwargs)

            model_fields = request.env['product.template']._fields.keys()
            fields = extract_valid_fields(
                kwargs.get('fields'),
                model_fields,
                ['id', 'name', 'default_code', 'list_price', 'qty_available']
            )

            if 'filter' in kwargs:
                domain = parse_filter_param(kwargs['filter'])
            else:
                domain = build_product_domain(kwargs)

            products = request.env['product.template'].search_read(
                domain=domain,
                fields=fields,
                limit=limit,
                offset=offset,
                order='id ASC'
            )

            total = self.get_product_count(domain)

            for product in products:
                invalidate_cache(f"product_data_{product['id']}")

            return http.Response(
                json.dumps({
                    'status': 'success',
                    'data': products,
                    'pagination': {
                        'limit': limit,
                        'offset': offset,
                        'total': total
                    }
                }),
                status=200,
                content_type='application/json'
            )

        except ValueError as ve:
            _logger.warning("Parameter error: %s", str(ve))
            return http.Response(json.dumps({'error': str(ve)}), status=400, content_type='application/json')

        except Exception as e:
            _logger.error("Unexpected error in get_products: %s", str(e))
            return http.Response(json.dumps({'error': 'Internal server error'}), status=500,
                                 content_type='application/json')

    @http.route('/api/stock', type='http', auth='none', methods=['GET'], csrf=False)
    @rate_limited(rate_limiter, max_requests=5, time_window=60)
    @require_auth
    def get_stock(self, **kwargs):
        try:

            limit, offset = validate_limit_offset(kwargs)

            if 'filter' in kwargs:
                domain = parse_stock_filter_param(kwargs['filter'])
            else:
                domain = build_stock_domain(kwargs)

            model_fields = request.env['stock.quant']._fields.keys()
            fields = extract_valid_fields(
                kwargs.get('fields'),
                model_fields,
                ['product_id', 'location_id', 'quantity']
            )

            results = self.get_cached_stock(domain, fields, limit, offset)
            total = self.get_stock_count(domain)

            for record in results:
                invalidate_cache(f"stock_quant_data_{record['product_id']}")

            return http.Response(
                json.dumps({
                    'status': 'success',
                    'data': results,
                    'pagination': {
                        'limit': limit,
                        'offset': offset,
                        'total': total
                    }
                }),
                status=200,
                content_type='application/json'
            )

        except ValueError as ve:
            _logger.warning("Invalid parameter: %s", str(ve))
            return http.Response(json.dumps({'error': str(ve)}), status=400, content_type='application/json')

        except Exception as e:
            _logger.error("Error in /api/stock: %s", str(e))
            return http.Response(json.dumps({'error': 'Internal server error'}), status=500,
                                 content_type='application/json')

    @http.route('/api/products/<int:product_id>', type='http', auth='none', methods=['GET'], csrf=False)
    @require_auth
    def get_product_by_id(self, product_id, **kwargs):
        try:
            fields_param = kwargs.get('fields', 'id,name,default_code,list_price,qty_available')
            valid_fields = request.env['product.template']._fields.keys()
            fields = [f for f in fields_param.split(',') if f in valid_fields]

            if not fields:
                return http.Response(json.dumps({'error': 'No valid fields selected'}), status=400,
                                     content_type='application/json')

            product = self.get_product_by_id_cached(product_id, fields)

            if not product:
                return http.Response(json.dumps({'error': 'Product not found or out of stock'}), status=404,
                                     content_type='application/json')

            return http.Response(json.dumps({
                'status': 'success',
                'data': product[0]
            }), status=200, content_type='application/json')

        except Exception as e:
            _logger.error("Error in /api/products/<id>: %s", str(e))
            return http.Response(json.dumps({'error': 'Internal server error'}), status=500,
                                 content_type='application/json')

    @http.route('/api/docs', type='http', auth='none', methods=['GET'], csrf=False)
    def api_docs(self, **kwargs):
        return http.Response(
            json.dumps({
                "title": "Inventory API Docs",
                "authentication": {
                    "type": "JWT",
                    "header": "Authorization: Bearer <token>",
                    "endpoint": "/api/login"
                },
                "endpoints": {
                    "/api/login": {
                        "method": "POST",
                        "description": "Authenticate user and receive JWT token",
                        "body": {
                            "username": "string",
                            "password": "string"
                        }
                    },
                    "/api/products": {
                        "method": "GET",
                        "description": "Retrieve product list with stock > 0",
                        "query_params": {
                            "limit": "int (1-1000)",
                            "offset": "int",
                            "fields": "Comma-separated field list",
                            "name": "Product name (partial match)",
                            "default_code": "Product internal reference",
                            "min_price": "Minimum price",
                            "max_price": "Maximum price",
                            "category_ids": "Comma-separated category IDs",
                            "category": "Category name"
                        }
                    },
                    "/api/products/<id>": {
                        "method": "GET",
                        "description": "Retrieve a single product by ID",
                        "path_param": {
                            "id": "Product Template ID"
                        },
                        "query_params": {
                            "fields": "Comma-separated list of fields"
                        }
                    },
                    "/api/stock": {
                        "method": "GET",
                        "description": "Get stock quantities from stock.quant",
                        "query_params": {
                            "location_id": "Optional stock location ID",
                            "fields": "Comma-separated list of fields",
                            "limit": "int",
                            "offset": "int"
                        }
                    }
                }
            }, indent=2, ensure_ascii=False),
            status=200,
            content_type='application/json'
        )

    @http.route('/api/health', type='http', auth='none', methods=['GET'], csrf=False, cors='*')
    @rate_limited(rate_limiter, max_requests=5, time_window=60)
    def health_check(self, **kwargs):

        _logger.info("Entering /api/health endpoint. Request headers: %s", http.request.httprequest.headers)

        try:

            _logger.debug("Starting health check process.")

            if not http.request.env:
                _logger.error("Request environment is not available.")
                return http.Response(
                    json.dumps({'status': 'error', 'message': 'Odoo environment unavailable'}),
                    status=500,
                    content_type='application/json'
                )

            _logger.debug("Testing database connection.")
            users = http.request.env['res.users'].sudo().search([], limit=1)
            if not users:
                _logger.warning("No users found in database, but connection succeeded.")
            else:
                _logger.debug("Database connection successful. Found %d users.", len(users))

            session = http.request.session
            if session:
                _logger.debug("Session found: sid=%s", session.sid)
            else:
                _logger.debug("No session available.")

            response_data = {'status': 'ok', 'message': 'Server is healthy', 'users_count': len(users)}
            _logger.info("Health check completed successfully. Response: %s", response_data)
            return http.Response(
                json.dumps(response_data),
                status=200,
                content_type='application/json'
            )

        except Exception as e:
            _logger.error("Health check failed: %s", str(e), exc_info=True)
            return http.Response(
                json.dumps({'status': 'error', 'message': str(e)}),
                status=500,
                content_type='application/json'
            )

    @http.route('/api/products/export', type='http', auth='none', methods=['GET'], csrf=False)
    @require_auth
    @rate_limited(rate_limiter, max_requests=2, time_window=60)
    @require_group('stock.group_stock_manager')
    def export_products_csv(self, **kwargs):
        try:

            limit, offset = validate_limit_offset(kwargs)

            model_fields = request.env['product.template']._fields.keys()
            fields = extract_valid_fields(
                kwargs.get('fields'),
                model_fields,
                ['id', 'name', 'default_code', 'list_price', 'qty_available']
            )

            domain = build_product_domain(kwargs)

            records = request.env['product.template'].search_read(
                domain=domain,
                fields=fields,
                limit=limit,
                offset=offset
            )

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for row in records:
                writer.writerow(row)

            csv_data = output.getvalue()
            output.close()

            for record in records:
                invalidate_cache(f"product_data_{record['id']}")

            headers = [
                ('Content-Type', 'text/csv'),
                ('Content-Disposition', 'attachment; filename=products.csv')
            ]

            return http.Response(csv_data, headers=headers)

        except ValueError as ve:
            _logger.warning("CSV export param error: %s", str(ve))
            return http.Response(json.dumps({'error': str(ve)}), status=400, content_type='application/json')

        except Exception as e:
            _logger.error("CSV export error: %s", str(e))
            return http.Response(json.dumps({'error': 'Internal server error'}), status=500,
                                 content_type='application/json')

    @http.route('/api/stock/export', type='http', auth='none', methods=['GET'], csrf=False)
    @require_auth
    @rate_limited(rate_limiter, max_requests=2, time_window=60)
    @require_group('stock.group_stock_manager')
    def export_stock_csv(self, **kwargs):
        try:

            limit, offset = validate_limit_offset(kwargs)

            domain = build_stock_domain(kwargs)

            model_fields = request.env['stock.quant']._fields.keys()
            fields = extract_valid_fields(
                kwargs.get('fields'),
                model_fields,
                ['product_id', 'location_id', 'quantity']
            )

            records = request.env['stock.quant'].sudo().search_read(
                domain=domain,
                fields=fields,
                limit=limit,
                offset=offset
            )

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for row in records:
                writer.writerow(row)

            for record in records:
                invalidate_cache(f"stock_quant_data_{record['product_id']}")

            csv_data = output.getvalue()
            output.close()

            headers = [
                ('Content-Type', 'text/csv'),
                ('Content-Disposition', 'attachment; filename=stock.csv')
            ]

            return http.Response(csv_data, headers=headers)

        except ValueError as ve:
            _logger.warning("CSV export stock param error: %s", str(ve))
            return http.Response(json.dumps({'error': str(ve)}), status=400, content_type='application/json')

        except Exception as e:
            _logger.error("CSV export stock error: %s", str(e))
            return http.Response(json.dumps({'error': 'Internal server error'}), status=500,
                                 content_type='application/json')
