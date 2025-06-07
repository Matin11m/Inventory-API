import base64
import csv
import io
import json
import logging
import os
import time
import traceback
from datetime import datetime, timedelta
from functools import wraps

import magic
from PIL import Image
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from odoo import http
from odoo.exceptions import AccessError, UserError, ValidationError
from odoo.http import request
from odoo.tools import cache
from odoo.tools import image_process
from ..utils import config, validators, response, logging as api_logging
from ..utils.auth import create_jwt_token, decode_jwt_token
from ..utils.dashboard import MonitoringDashboard
from ..utils.json_filter import parse_filter_param, parse_customer_filter_param
from ..utils.json_filter import parse_stock_filter_param
from ..utils.logging import log_error
from ..utils.product import get_stock_location, check_duplicates
from ..utils.query import build_product_domain, get_customer_by_id, get_customer_count, build_customer_domain
from ..utils.query import build_stock_domain
from ..utils.rate_limit import rate_limited, RateLimiter
from ..utils.validators import validate_limit_offset, extract_valid_fields, validate_username, validate_password, \
    validate_invoice_data, validate_invoice_line, validate_customer_data, validate_limit_offset2

_logger = logging.getLogger(__name__)
rate_limiter = RateLimiter()
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


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

    # @cache(timeout=300)
    # def get_customer_count(self, domain):
    #     _logger.debug("Counting customers with domain: %s", domain)
    #     return request.env['res.partner'].with_user(request.env.user).search_count(domain)
    #
    # @cache(timeout=300)
    # def get_customer_by_id_cached(self, customer_id, fields):
    #     _logger.debug("Fetching customer by ID: %s, fields: %s", customer_id, fields)
    #     return request.env['res.partner'].with_user(request.env.user).search_read(
    #         domain=[('id', '=', customer_id)],
    #         fields=fields,
    #         limit=1
    #     )

    @http.route('/api/login', type='http', auth='none', methods=['POST'], csrf=False)
    @rate_limited(rate_limiter, max_requests=3, time_window=60)
    def login(self, **kwargs):
        try:
            _logger.info("Login request received for username: %s", kwargs.get('username', 'unknown'))
            data = json.loads(request.httprequest.data.decode('utf-8'))
            username = data.get('username')
            password = data.get('password')

            validate_username(username)
            validate_password(password)

            if not username or not password:
                _logger.error("Login failed: Missing username or password")
                raise ValueError("Username and password required")

            user = request.env['res.users'].sudo().search([('login', '=', username)], limit=1)
            if not user.exists():
                _logger.error("Login failed: User not found for username: %s", username)
                raise ValueError("User not found")

            request.env.cr.execute("SELECT COALESCE(password, '') FROM res_users WHERE id=%s", (user.id,))
            hashed = request.env.cr.fetchone()[0]
            if not hashed or not request.env['res.users']._crypt_context().verify(password, hashed):
                _logger.error("Login failed: Invalid password for user ID: %s", user.id)
                raise ValueError("Invalid password")

            token = create_jwt_token(user.id)
            _logger.info("Login successful for user ID: %s", user.id)
            return http.Response(
                json.dumps({'token': token}),
                status=200,
                content_type='application/json'
            )

        except ValueError as e:
            log_error("Login error", e)
            return http.Response(
                json.dumps({'error': str(e)}),
                status=401,
                content_type='application/json'
            )
        except Exception as e:
            log_error("Unexpected login error", e)
            return http.Response(
                json.dumps({'error': 'Internal server error'}),
                status=500,
                content_type='application/json'
            )

    @http.route('/api/products', type='http', auth='none', methods=['GET'], csrf=False)
    @rate_limited(rate_limiter, max_requests=5, time_window=60)
    @require_auth
    def get_products(self, **kwargs):
        try:
            limit, offset = validate_limit_offset(kwargs)

            model_fields = request.env['product.product']._fields.keys()
            fields = extract_valid_fields(
                kwargs.get('fields'),
                model_fields,
                ['id', 'name', 'default_code', 'list_price', 'qty_available']
            )

            if 'filter' in kwargs:
                domain = parse_filter_param(kwargs['filter'])
            else:
                domain = build_product_domain(kwargs)

            products = request.env['product.product'].search_read(
                domain=domain,
                fields=fields,
                limit=limit,
                offset=offset,
                order='id ASC'
            )

            total = request.env['product.product'].search_count(domain)

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

            results = request.env['stock.quant'].search_read(
                domain=domain,
                fields=fields,
                limit=limit,
                offset=offset,
                order='id ASC'
            )

            total = request.env['stock.quant'].search_count(domain)

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
            valid_fields = request.env['product.product']._fields.keys()
            fields = [f for f in fields_param.split(',') if f in valid_fields]

            if not fields:
                return http.Response(
                    json.dumps({'error': 'No valid fields selected'}),
                    status=400,
                    content_type='application/json'
                )

            product = request.env['product.product'].search_read(
                [('id', '=', product_id)],
                fields,
                limit=1
            )

            if not product:
                return http.Response(
                    json.dumps({'error': 'Product not found or out of stock'}),
                    status=404,
                    content_type='application/json'
                )

            return http.Response(
                json.dumps({
                    'status': 'success',
                    'data': product[0]
                }),
                status=200,
                content_type='application/json'
            )

        except Exception as e:
            _logger.error("Error in /api/products/%s: %s", product_id, str(e))
            return http.Response(
                json.dumps({'error': 'Internal server error'}),
                status=500,
                content_type='application/json'
            )

    # @http.route('/api/docs', type='http', auth='none', methods=['GET'], csrf=False)
    # def api_docs(self, **kwargs):
    #     return http.Response(
    #         json.dumps({
    #             "title": "Inventory API Docs",
    #             "authentication": {
    #                 "type": "JWT",
    #                 "header": "Authorization: Bearer <token>",
    #                 "endpoint": "/api/login"
    #             },
    #             "endpoints": {
    #                 "/api/login": {
    #                     "method": "POST",
    #                     "description": "Authenticate user and receive JWT token",
    #                     "body": {
    #                         "username": "string",
    #                         "password": "string"
    #                     }
    #                 },
    #                 "/api/products": {
    #                     "method": "GET",
    #                     "description": "Retrieve product list with stock > 0",
    #                     "query_params": {
    #                         "limit": "int (1-1000)",
    #                         "offset": "int",
    #                         "fields": "Comma-separated field list",
    #                         "name": "Product name (partial match)",
    #                         "default_code": "Product internal reference",
    #                         "min_price": "Minimum price",
    #                         "max_price": "Maximum price",
    #                         "category_ids": "Comma-separated category IDs",
    #                         "category": "Category name"
    #                     }
    #                 },
    #                 "/api/products/<id>": {
    #                     "method": "GET",
    #                     "description": "Retrieve a single product by ID",
    #                     "path_param": {
    #                         "id": "Product Template ID"
    #                     },
    #                     "query_params": {
    #                         "fields": "Comma-separated list of fields"
    #                     }
    #                 },
    #                 "/api/stock": {
    #                     "method": "GET",
    #                     "description": "Get stock quantities from stock.quant",
    #                     "query_params": {
    #                         "location_id": "Optional stock location ID",
    #                         "fields": "Comma-separated list of fields",
    #                         "limit": "int",
    #                         "offset": "int"
    #                     }
    #                 },
    #                 "/api/products/export": {
    #                     "method": "GET",
    #                     "description": "Export products to CSV with stock > 0",
    #                     "query_params": {
    #                         "limit": "int (1-1000, optional)",
    #                         "offset": "int (optional)",
    #                         "fields": "Comma-separated field list (default: id, name, default_code, list_price, qty_available)",
    #                         "name": "Product name (partial match, optional)",
    #                         "default_code": "Product internal reference (optional)",
    #                         "min_price": "Minimum price (optional)",
    #                         "max_price": "Maximum price (optional)",
    #                         "category_ids": "Comma-separated category IDs (optional)",
    #                         "category": "Category name (optional)"
    #                     }
    #                 },
    #                 "/api/stock/export": {
    #                     "method": "GET",
    #                     "description": "Export stock quantities to CSV from stock.quant",
    #                     "query_params": {
    #                         "location_id": "Optional stock location ID",
    #                         "fields": "Comma-separated list of fields (default: product_id, location_id, quantity)",
    #                         "limit": "int (optional)",
    #                         "offset": "int (optional)"
    #                     }
    #                 },
    #                 "/api/products/upload": {
    #                     "method": "POST",
    #                     "description": "Upload products via JSON file, raw JSON data, or form data with optional images",
    #                     "content_type": "multipart/form-data or application/json",
    #                     "form_data": {
    #                         "products": "file (JSON file containing a list of products, optional)",
    #                         "products_json": "string (JSON string containing a list of products, optional if 'products' file not provided)",
    #                         "images": "files (optional list of image files, max 5MB each, formats: jpg, jpeg, png, max count defined by config.MAX_IMAGES)"
    #                     },
    #                     "body": {
    #                         "description": "If using raw JSON (Content-Type: application/json), the body must be a list of products",
    #                         "items": {
    #                             "name": "string (required, product name)",
    #                             "default_code": "string (optional, product internal reference)",
    #                             "list_price": "number (optional, product price)",
    #                             "qty_available": "number (optional, initial stock quantity)",
    #                             "additional_fields": "other fields as allowed by config.ALLOWED_FIELDS"
    #                         }
    #                     },
    #                     "limits": {
    #                         "max_products": f"int (defined by config.MAX_PRODUCTS, e.g., {config.MAX_PRODUCTS})",
    #                         "max_images": f"int (defined by config.MAX_IMAGES, e.g., {config.MAX_IMAGES})",
    #                         "max_image_size": "5MB per image"
    #                     }
    #                 },
    #                 "/api/products/update_stock": {
    #                     "method": "POST",
    #                     "description": "Update stock quantities for products using default_code or name",
    #                     "content_type": "application/json",
    #                     "body": {
    #                         "description": "List of products to update stock",
    #                         "items": {
    #                             "default_code": "string (required, product internal reference)",
    #                             "name": "string (required, product name)",
    #                             "quantity": "number (required, quantity to add or delete, must be positive)",
    #                             "operation": "string (required, either 'add' to increase stock or 'delete' to decrease stock)"
    #                         }
    #                     }
    #                 },
    #                 "/api/invoices/create": {
    #                     "method": "POST",
    #                     "description": "Create a new invoice in the system",
    #                     "body": {
    #                         "customer_id": "integer (ID of the customer)",
    #                         "invoice_date": "string (date in YYYY-MM-DD format)",
    #                         "due_date": "string (date in YYYY-MM-DD format, optional)",
    #                         "post_immediately": "boolean (whether to post immediately)",
    #                         "invoice_lines": {
    #                             "type": "array",
    #                             "items": {
    #                                 "product_id": "integer (ID of the product)",
    #                                 "quantity": "number (quantity of the product)",
    #                                 "price_unit": "number (unit price of the product)",
    #                                 "description": "string (optional description)"
    #                             }
    #                         }
    #                     }
    #                 }
    #             }
    #         }, indent=2, ensure_ascii=False),
    #         status=200,
    #         content_type='application/json'
    #     )

    @http.route('/api/redoc', type='http', auth='none', methods=['GET'], csrf=False)
    def redoc_docs(self, **kwargs):
        module_path = os.path.dirname(os.path.abspath(__file__))
        redoc_path = os.path.join(module_path, '../static/redoc.html')

        with open(redoc_path, 'r') as file:
            redoc_html = file.read()

        return http.Response(
            redoc_html,
            status=200,
            content_type='text/html'
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
    @rate_limited(rate_limiter, max_requests=2, time_window=60)
    @require_auth
    def export_products_csv(self, **kwargs):
        try:
            limit, offset = validate_limit_offset(kwargs)

            model_fields = request.env['product.product']._fields.keys()
            fields = extract_valid_fields(
                kwargs.get('fields'),
                model_fields,
                ['id', 'name', 'default_code', 'list_price', 'qty_available']
            )

            domain = build_product_domain(kwargs)

            records = request.env['product.product'].search_read(
                domain=domain,
                fields=fields,
                limit=limit,
                offset=offset
            )

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for row in records:
                row_copy = row.copy()
                for key in list(row_copy.keys()):
                    if key not in fields:
                        row_copy.pop(key, None)
                writer.writerow(row_copy)

            csv_data = output.getvalue()
            output.close()

            headers = [
                ('Content-Type', 'text/csv'),
                ('Content-Disposition', 'attachment; filename=products.csv')
            ]

            return http.Response(csv_data, headers=headers)

        except ValueError as ve:
            _logger.warning("CSV export param error: %s", str(ve))
            return http.Response(json.dumps({'error': str(ve)}), status=400, content_type='application/json')
        except AccessError:
            _logger.error("Access denied: User lacks product access permissions")
            return http.Response(json.dumps({'error': 'Access denied: Requires product access permissions'}),
                                 status=403, content_type='application/json')
        except Exception as e:
            _logger.error("CSV export error: %s", str(e))
            return http.Response(json.dumps({'error': 'Internal server error'}), status=500,
                                 content_type='application/json')

    @http.route('/api/stock/export', type='http', auth='none', methods=['GET'], csrf=False)
    @rate_limited(rate_limiter, max_requests=2, time_window=60)
    @require_auth
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

            records = request.env['stock.quant'].search_read(
                domain=domain,
                fields=fields,
                limit=limit,
                offset=offset
            )

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for row in records:
                row_copy = row.copy()
                row_copy.pop('id', None)
                if 'product_id' in row_copy:
                    row_copy['product_id'] = row_copy['product_id'][0] if isinstance(row_copy['product_id'],
                                                                                     (list, tuple)) else row_copy[
                        'product_id']
                if 'location_id' in row_copy:
                    row_copy['location_id'] = row_copy['location_id'][0] if isinstance(row_copy['location_id'],
                                                                                       (list, tuple)) else row_copy[
                        'location_id']
                writer.writerow(row_copy)

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

    @http.route('/api/products/upload', type='http', auth='public', methods=['POST'], csrf=False)
    @rate_limited(rate_limiter, max_requests=10, time_window=300)
    @require_auth
    def upload_products(self, **kwargs):
        start_time = time.time()
        user_id = request.env.user.id
        status_code = 200
        response_data = {}

        try:
            if not request.env['product.product'].check_access_rights('create', raise_exception=False):
                raise AccessError("Access denied: Requires product creation permissions")
            if not request.env['stock.quant'].check_access_rights('create', raise_exception=False):
                raise AccessError("Access denied: Requires stock update permissions")

            products_data = []
            files = request.httprequest.files.getlist('products')
            if files:
                if len(files) > 1:
                    raise ValueError("Only one JSON file is allowed")
                file = files[0]
                if file and file.filename.endswith('.json'):
                    content = file.read().decode('utf-8')
                    products = json.loads(content)
                    if not isinstance(products, list):
                        raise ValueError("JSON file must contain a list of products")
                    products_data.extend(products)
            else:
                products_json = request.httprequest.form.get('products_json')
                if products_json:
                    products = json.loads(products_json)
                    if not isinstance(products, list):
                        raise ValueError("Input must be a list of products")
                    products_data.extend(products)
                else:
                    raw_data = request.httprequest.get_data().decode('utf-8')
                    if raw_data:
                        products = json.loads(raw_data)
                        if not isinstance(products, list):
                            raise ValueError("Input must be a list of products")
                        products_data.extend(products)

            if not products_data:
                raise ValueError("Product list cannot be empty")
            if len(products_data) > config.MAX_PRODUCTS:
                raise ValueError(f"Too many products. Maximum allowed is {config.MAX_PRODUCTS}")
            validators.validate_json_input(products_data, max_items=config.MAX_PRODUCTS)

            stock_location = get_stock_location(request.env)
            if not stock_location:
                raise ValueError("No stock location found")

            validated_products = []
            images = request.httprequest.files.getlist('images')
            if len(images) > config.MAX_IMAGES:
                raise ValueError(f"Too many images. Maximum allowed is {config.MAX_IMAGES}")

            processed_images = []
            for idx, product_data in enumerate(products_data):
                validated_product = validators.validate_product_data(product_data, config.ALLOWED_FIELDS, idx)
                validated_products.append(validated_product)

                processed_image_base64 = None
                if idx < len(images) and images[idx]:
                    image_file = images[idx]
                    if image_file and image_file.filename:
                        image_data = image_file.read()
                        if not any(
                                image_file.filename.lower().endswith(ext) for ext in config.ALLOWED_IMAGE_EXTENSIONS):
                            raise ValueError(f"Unsupported image format for file: {image_file.filename}")
                        if len(image_data) > 5 * 1024 * 1024:  # 5MB limit
                            raise ValueError(f"Image size exceeds 5MB limit for file: {image_file.filename}")
                        mime_type = magic.from_buffer(image_data, mime=True)
                        if mime_type not in config.ALLOWED_IMAGE_MIME_TYPES:
                            raise ValueError(f"Invalid image mime-type for file: {image_file.filename}")
                        try:
                            with Image.open(io.BytesIO(image_data)) as image:
                                image.verify()
                                image.format
                        except Exception as e:
                            raise ValueError(f"Invalid image format for file: {image_file.filename} - {str(e)}")
                        try:
                            processed_image = image_process(image_data, size=(1024, 1024), crop=False)
                            processed_image_base64 = base64.b64encode(processed_image)
                        except UserError as ue:
                            raise ValueError(f"Failed to process image {image_file.filename}: {str(ue)}")
                processed_images.append(processed_image_base64)

            unique_products, skipped_products = check_duplicates(request.env, validated_products)

            created_products = []
            product_records = []
            for idx, product_data in enumerate(unique_products):
                product = request.env['product.product'].create(product_data)
                if isinstance(product, int):
                    product = request.env['product.product'].browse(product)
                created_products.append(product.id)
                product_records.append(product)
                if idx < len(processed_images) and processed_images[idx]:
                    product.image_1920 = processed_images[idx]

            quant_vals = [{
                'product_id': pid,
                'location_id': stock_location.id,
                'quantity': 0
            } for pid in created_products]
            if quant_vals:
                request.env['stock.quant'].create(quant_vals)

            response_time_ms = (time.time() - start_time) * 1000
            resp = response.build_response(
                len(created_products),
                created_products,
                skipped_products,
                response_time_ms
            )
            response_data = json.loads(resp.get_data(as_text=True))
            status_code = resp.status_code

            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/products/upload',
                request_data=json.dumps(products_data),
                response_data=response_data,
                status_code=status_code,
                response_time_ms=response_time_ms,
                log_level='info'
            )

            return resp

        except ValueError as ve:
            response_time_ms = (time.time() - start_time) * 1000
            resp = response.handle_error(str(ve), status_code=400)
            response_data = json.loads(resp.get_data(as_text=True))
            status_code = resp.status_code
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/products/upload',
                request_data=f"ValueError: {str(ve)}",
                response_data={},
                status_code=status_code,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            return resp
        except AccessError as ae:
            response_time_ms = (time.time() - start_time) * 1000
            resp = response.handle_error("Access denied: Insufficient permissions", status_code=403)
            response_data = json.loads(resp.get_data(as_text=True))
            status_code = resp.status_code
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/products/upload',
                request_data="AccessError occurred",
                response_data={},
                status_code=status_code,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            return resp
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/products/upload',
                request_data=f"Unexpected error: {str(e)}\n{traceback.format_exc()}",
                response_data={},
                status_code=500,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            resp = response.handle_error("An error occurred", status_code=500)
            response_data = json.loads(resp.get_data(as_text=True))
            status_code = resp.status_code
            return resp

    @http.route('/api/products/update_stock', type='http', auth='public', methods=['POST'], csrf=False)
    @rate_limited(rate_limiter, max_requests=20, time_window=600)
    @require_auth
    def update_stock(self, **kwargs):
        start_time = time.time()
        user_id = request.env.user.id
        ip = request.httprequest.remote_addr
        status_code = 200
        response_data = {}

        try:
            if not request.env['stock.quant'].check_access_rights('write', raise_exception=False):
                raise AccessError("Access denied: Requires stock update permissions")

            raw_data = request.httprequest.get_data().decode('utf-8')
            if not raw_data:
                raise ValueError("Request body cannot be empty")
            products_data = json.loads(raw_data)
            if not isinstance(products_data, list):
                raise ValueError("Input must be a list of products")
            if not products_data:
                raise ValueError("Product list cannot be empty")

            invalid_entries = []
            for idx, product_data in enumerate(products_data):
                default_code = product_data.get('default_code', '')
                name = product_data.get('name', '')
                quantity = product_data.get('quantity')
                operation = product_data.get('operation', '')
                if any(char in default_code for char in '<>"\'') or any(char in name for char in '<>"\'') or any(
                        char in operation for char in '<>"\''):
                    invalid_entries.append((idx, "Invalid characters detected in input"))
                if not default_code or not name:
                    invalid_entries.append((idx, "Both default_code and name are required"))
                elif not isinstance(quantity, (int, float)) or quantity <= 0:
                    invalid_entries.append((idx, "Invalid quantity"))
                elif operation not in ['add', 'delete']:
                    invalid_entries.append((idx, "Operation must be 'add' or 'delete'"))
            if invalid_entries:
                raise ValueError("\n".join(f"Index {idx}: {msg}" for idx, msg in invalid_entries))

            stock_location = get_stock_location(request.env)
            if not stock_location:
                raise ValueError("No stock location found")

            default_codes = [p.get('default_code') for p in products_data if p.get('default_code')]
            names = [p.get('name') for p in products_data if p.get('name')]
            products = request.env['product.product'].search([
                '|', ('default_code', 'in', default_codes),
                ('name', 'in', names)
            ])
            product_dict = {p.default_code or p.name: p for p in products}

            quants = request.env['stock.quant'].search([
                ('product_id', 'in', products.ids),
                ('location_id', '=', stock_location)
            ])
            quant_dict = {(q.product_id.id, stock_location): q for q in quants}

            updated_products = []
            failed_products = []
            for idx, product_data in enumerate(products_data):
                default_code = product_data.get('default_code')
                name = product_data.get('name')
                quantity = int(product_data.get('quantity'))
                operation = product_data.get('operation')

                identifier = default_code or name
                product_record = product_dict.get(identifier)
                if not product_record:
                    failed_products.append({
                        'identifier': identifier or f"index {idx}",
                        'error': "Product not found"
                    })
                    continue

                quant_key = (product_record.id, stock_location)
                stock_quant = quant_dict.get(quant_key)
                if not stock_quant:
                    if operation == 'delete':
                        failed_products.append({
                            'identifier': identifier,
                            'error': "No stock found for this product in the location"
                        })
                        continue
                    stock_quant = request.env['stock.quant'].create({
                        'product_id': product_record.id,
                        'location_id': stock_location,
                        'quantity': 0
                    })
                    quant_dict[quant_key] = stock_quant

                current_quantity = int(stock_quant.quantity)
                if operation == 'add':
                    new_quantity = current_quantity + quantity
                    stock_quant.write({'quantity': new_quantity})
                    updated_products.append({
                        'identifier': identifier,
                        'operation': operation,
                        'quantity': quantity
                    })
                elif operation == 'delete':
                    if current_quantity < quantity:
                        failed_products.append({
                            'identifier': identifier,
                            'error': f"Insufficient stock (available: {current_quantity}, requested: {quantity})"
                        })
                        continue
                    new_quantity = current_quantity - quantity
                    stock_quant.write({'quantity': new_quantity})
                    updated_products.append({
                        'identifier': identifier,
                        'operation': operation,
                        'quantity': quantity
                    })

            response_time_ms = (time.time() - start_time) * 1000
            resp = response.build_response_update_stock(
                updated_products,
                failed_products,
                response_time_ms
            )
            response_data = json.loads(resp.get_data(as_text=True))
            status_code = resp.status_code

            request_data = json.dumps(
                products_data) if 'Authorization' not in request.httprequest.headers else "Sensitive data masked"
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/products/update_stock',
                request_data=request_data,
                response_data=response_data,
                status_code=status_code,
                response_time_ms=response_time_ms,
                log_level='info'
            )

            return resp

        except ValueError as ve:
            response_time_ms = (time.time() - start_time) * 1000
            resp = response.handle_error(str(ve), status_code=400)
            response_data = json.loads(resp.get_data(as_text=True))
            status_code = resp.status_code
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/products/update_stock',
                request_data=f"ValueError: {str(ve)}\n{traceback.format_exc()}",
                response_data={},
                status_code=status_code,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            return resp
        except AccessError as ae:
            response_time_ms = (time.time() - start_time) * 1000
            resp = response.handle_error("Access denied: Insufficient permissions", status_code=403)
            response_data = json.loads(resp.get_data(as_text=True))
            status_code = resp.status_code
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/products/update_stock',
                request_data=f"AccessError: {str(ae)}\n{traceback.format_exc()}",
                response_data={},
                status_code=status_code,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            return resp
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/products/update_stock',
                request_data=f"Unexpected error: {str(e)}\n{traceback.format_exc()}",
                response_data={},
                status_code=500,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            resp = response.handle_error("An error occurred", status_code=500)
            response_data = json.loads(resp.get_data(as_text=True))
            status_code = resp.status_code
            return resp

    def get_customer_count(self, domain):
        _logger.debug("Counting customers with domain: %s", domain)
        return request.env['res.partner'].with_user(request.env.user).search_count(domain)

    def get_customer_by_id_cached(self, customer_id, fields):
        _logger.debug("Fetching customer by ID: %s, fields: %s", customer_id, fields)
        return request.env['res.partner'].with_user(request.env.user).search_read(
            domain=[('id', '=', customer_id)],
            fields=fields,
            limit=1
        )

    @http.route('/api/customers', type='http', auth='none', methods=['POST'], csrf=False)
    @require_auth
    @rate_limited(rate_limiter,max_requests=50, time_window=3600)
    def create_customer(self, **kwargs):

        try:
            data = json.loads(request.httprequest.data.decode('utf-8'))
            validated_data = validate_customer_data(data)

            customer = request.env['res.partner'].with_user(request.env.user).create(validated_data)

            return http.Response(
                json.dumps({
                    'status': 'success',
                    'data': {
                        'id': customer.id,
                        'name': customer.name,
                        'email': customer.email,
                        'phone': customer.phone,
                        'street': customer.street
                    }
                }),
                status=201,
                content_type='application/json'
            )

        except ValueError as ve:
            _logger.warning("Invalid customer data: %s", str(ve))
            return http.Response(json.dumps({'error': str(ve)}), status=400, content_type='application/json')
        except Exception as e:
            _logger.error("Error creating customer: %s\n%s", str(e), traceback.format_exc())
            return http.Response(json.dumps({'error': 'Internal server error'}), status=500,
                                 content_type='application/json')

    @http.route('/api/customers', type='http', auth='none', methods=['GET'], csrf=False)
    @require_auth
    @rate_limited(rate_limiter,max_requests=100, time_window=3600)
    def get_customers(self, **kwargs):

        try:
            limit, offset = validate_limit_offset2(kwargs)
            model_fields = request.env['res.partner']._fields.keys()
            fields = extract_valid_fields(
                kwargs.get('fields'),
                model_fields,
                ['id', 'name', 'email', 'phone', 'street']
            )

            if 'filter' in kwargs:
                domain = parse_customer_filter_param(kwargs['filter'])
            else:
                domain = build_customer_domain(kwargs)

            customers = request.env['res.partner'].with_user(request.env.user).search_read(
                domain=domain,
                fields=fields,
                limit=limit,
                offset=offset,
                order='id'
            )

            total = get_customer_count(domain)

            return http.Response(
                json.dumps({
                    'status': 'success',
                    'data': customers,
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
            _logger.error("Unexpected error in get_customers: %s\n%s", str(e), traceback.format_exc())
            return http.Response(json.dumps({'error': str(e)}), status=500, content_type='application/json')

    @http.route('/api/customers/<int:customer_id>', type='http', auth='none', methods=['GET'], csrf=False)
    @require_auth
    @rate_limited(rate_limiter,max_requests=100, time_window=3600)
    def get_customer_by_id(self, customer_id, **kwargs):

        try:
            fields_param = kwargs.get('fields', 'id,name,email,phone,street')
            valid_fields = request.env['res.partner']._fields.keys()
            fields = [f.strip() for f in fields_param.split(',') if f.strip() in valid_fields]

            if not fields:
                return http.Response(json.dumps({'error': 'No valid fields selected'}), status=400,
                                     content_type='application/json')

            customer = get_customer_by_id(customer_id, fields)

            if not customer:
                return http.Response(json.dumps({'error': 'Customer not found'}), status=404,
                                     content_type='application/json')

            return http.Response(
                json.dumps({
                    'status': 'success',
                    'data': customer[0]
                }),
                status=200,
                content_type='application/json'
            )

        except ValueError as ve:
            _logger.warning("Parameter error: %s", str(ve))
            return http.Response(json.dumps({'error': str(ve)}), status=400, content_type='application/json')
        except Exception as e:
            _logger.error("Error in /api/customers/<id>: %s\n%s", str(e), traceback.format_exc())
            return http.Response(json.dumps({'error': str(e)}), status=500, content_type='application/json')


class InvoiceController(http.Controller):

    @http.route('/api/invoices/create', type='http', auth='public', methods=['POST'], csrf=False)
    @rate_limited(rate_limiter, max_requests=20, time_window=600)
    @require_auth
    def create_invoice(self, **kwargs):
        start_time = time.time()
        user_id = request.env.user.id
        status_code = 200

        try:
            if not request.env['account.move'].check_access_rights('create', raise_exception=False):
                raise AccessError("Access denied: Requires invoice creation permissions")

            raw_data = request.httprequest.get_data().decode('utf-8')
            if not raw_data:
                raise ValidationError("No data provided")

            try:
                data = json.loads(raw_data)
            except json.JSONDecodeError as e:
                raise ValidationError(f"Invalid JSON format: {str(e)}")

            validated_data = validate_invoice_data(data)
            customer_id = validated_data['customer_id']
            invoice_date = validated_data['invoice_date']
            due_date = validated_data['due_date']
            post_immediately = validated_data['post_immediately']
            invoice_lines = validated_data['invoice_lines']

            if not request.env['res.partner'].check_access_rights('read', raise_exception=False):
                raise AccessError("Access denied: Requires read permissions for partners")

            customer = request.env['res.partner'].browse(customer_id)
            if not customer.exists():
                raise ValidationError(f"Customer with ID {customer_id} not found")
            try:
                customer.check_access_rule('read')
            except AccessError as ae:
                raise AccessError(f"Access denied: No read permission for customer with ID {customer_id}")

            if not request.env['product.product'].check_access_rights('read', raise_exception=False):
                raise AccessError("Access denied: Requires read permissions for products")

            line_vals = []
            for idx, line in enumerate(invoice_lines):
                validated_line = validate_invoice_line(line, idx)
                product_id = validated_line['product_id']
                quantity = validated_line['quantity']
                price_unit = validated_line['price_unit']
                description = validated_line['description']
                tax_ids = validated_line['tax_ids']

                product = request.env['product.product'].browse(product_id)
                if not product.exists():
                    raise ValidationError(f"Line {idx}: Product with ID {product_id} not found")
                try:
                    product.check_access_rule('read')
                except AccessError as ae:
                    raise AccessError(f"Access denied: No read permission for product with ID {product_id}")

                line_vals.append({
                    'product_id': product_id,
                    'name': description if description else product.name,
                    'quantity': quantity,
                    'price_unit': price_unit,
                    'tax_ids': [(6, 0, tax_ids)] if tax_ids else False,
                })

            invoice_vals = {
                'partner_id': customer_id,
                'invoice_date': invoice_date,
                'invoice_date_due': due_date if due_date else False,
                'move_type': 'out_invoice',
                'invoice_line_ids': [(0, 0, line) for line in line_vals],
            }

            if not request.env['account.move'].check_access_rights('write', raise_exception=False):
                raise AccessError("Access denied: Requires write permissions for invoices")

            with request.env.cr.savepoint():
                invoice = request.env['account.move'].create(invoice_vals)
                try:
                    invoice.check_access_rule('write')
                except AccessError as ae:
                    raise AccessError("Access denied: No write permission for created invoice")

                if post_immediately:
                    if not request.env['account.move'].check_access_rights('write', raise_exception=False):
                        raise AccessError("Access denied: Requires write permissions to post invoices")
                    invoice.action_post()

            response_time_ms = (time.time() - start_time) * 1000

            resp = response.build_response_create_invoice(
                invoice_id=invoice.id,
                invoice_number=invoice.name,
                response_time_ms=response_time_ms
            )

            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/invoices/create',
                request_data=json.dumps(data),
                response_data={'invoice_id': invoice.id, 'invoice_number': invoice.name},
                status_code=200,
                response_time_ms=response_time_ms,
                log_level='info'
            )

            return resp

        except (ValidationError, ValueError) as ve:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(f"Validation error: {str(ve)}")
            resp = response.handle_error(str(ve), status_code=400)
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/invoices/create',
                request_data=f"ValidationError: {str(ve)}",
                response_data={},
                status_code=400,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            return resp

        except AccessError as ae:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(f"AccessError: {str(ae)}")
            resp = response.handle_error(str(ae), status_code=403)
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/invoices/create',
                request_data="AccessError occurred",
                response_data={},
                status_code=403,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            return resp

        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(f"Unexpected error: {str(e)}")
            resp = response.handle_error("An unexpected error occurred", status_code=500)
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/invoices/create',
                request_data="Unexpected error occurred",
                response_data={},
                status_code=500,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            return resp


class MonitoringController(http.Controller):

    @http.route('/api/monitoring/dashboard', type='http', auth='user', methods=['GET'])
    def monitoring_dashboard(self, hours=24, **kwargs):
        """Get monitoring dashboard data"""
        try:
            hours = int(hours)
            dashboard = MonitoringDashboard(request.env)
            data = dashboard.get_dashboard_data(hours)

            return http.Response(
                json.dumps(data, default=str),
                content_type='application/json'
            )
        except Exception as e:
            return http.Response(
                json.dumps({'error': str(e)}),
                status=500,
                content_type='application/json'
            )

    @http.route('/api/monitoring/alerts', type='http', auth='user', methods=['GET'])
    def get_alerts(self, **kwargs):
        """Get active alerts"""
        try:
            alerts = request.env['api.alert'].search([
                ('is_resolved', '=', False)
            ], order='severity desc, timestamp desc')

            alert_data = []
            for alert in alerts:
                alert_data.append({
                    'id': alert.id,
                    'type': alert.alert_type,
                    'severity': alert.severity,
                    'endpoint': alert.endpoint,
                    'message': alert.message,
                    'timestamp': alert.timestamp.isoformat(),
                    'metric_value': alert.metric_value,
                    'threshold_value': alert.threshold_value,
                })

            return http.Response(
                json.dumps(alert_data),
                content_type='application/json'
            )
        except Exception as e:
            return http.Response(
                json.dumps({'error': str(e)}),
                status=500,
                content_type='application/json'
            )

    @http.route('/api/monitoring/metrics/export', type='http', auth='user', methods=['GET'])
    def export_metrics(self, hours=24, format='json', **kwargs):
        """Export metrics data"""
        try:
            hours = int(hours)
            time_range = datetime.now() - timedelta(hours=hours)

            metrics = request.env['api.metrics'].search_read([
                ('timestamp', '>=', time_range)
            ], limit=None)

            if format == 'csv':
                # Return CSV format
                import csv
                import io

                output = io.StringIO()
                if metrics:
                    writer = csv.DictWriter(output, fieldnames=metrics[0].keys())
                    writer.writeheader()
                    writer.writerows(metrics)

                return http.Response(
                    output.getvalue(),
                    headers=[
                        ('Content-Type', 'text/csv'),
                        ('Content-Disposition', 'attachment; filename=api_metrics.csv')
                    ]
                )
            else:
                # Return JSON format
                return http.Response(
                    json.dumps(metrics, default=str),
                    content_type='application/json'
                )

        except Exception as e:
            return http.Response(
                json.dumps({'error': str(e)}),
                status=500,
                content_type='application/json'
            )
