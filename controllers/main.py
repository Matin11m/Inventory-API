import base64
import csv
import io
import json
import logging
import time
from functools import wraps

import magic
from PIL import Image
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from odoo import http
from odoo.exceptions import AccessError, UserError
from odoo.http import request
from odoo.tools import cache
from odoo.tools import image_process
from ..utils import config, validators, response, logging as api_logging
from ..utils.auth import create_jwt_token, decode_jwt_token
from ..utils.json_filter import parse_filter_param
from ..utils.json_filter import parse_stock_filter_param
from ..utils.logging import log_error
from ..utils.product import get_stock_location, check_duplicates
from ..utils.query import build_product_domain
from ..utils.query import build_stock_domain
from ..utils.rate_limit import rate_limited, RateLimiter
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
    @rate_limited(rate_limiter=rate_limiter, max_requests=10, time_window=300)
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
            for idx, product_data in enumerate(unique_products):
                product = request.env['product.product'].create(product_data)
                created_products.append(product.id)
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
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            api_logging.log_api_request(
                env=request.env,
                user_id=user_id,
                method=request.httprequest.method,
                endpoint='/api/products/upload',
                request_data=f"Unexpected error: {str(e)}",
                response_data={},
                status_code=500,
                response_time_ms=response_time_ms,
                log_level='error'
            )
            resp = response.handle_error("An error occurred", status_code=500)
            response_data = json.loads(resp.get_data(as_text=True))
            status_code = resp.status_code

        return resp