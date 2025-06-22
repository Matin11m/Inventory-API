import logging
from odoo.http import Response
import json
from odoo import http
import sys

_logger = logging.getLogger(__name__)


def build_response(created_count, product_ids, skipped_products, elapsed_time):
    response_message = {
        'created': created_count,
        'product_ids': product_ids,
        'skipped': skipped_products,
        'response_time_ms': elapsed_time
    }
    if skipped_products and created_count == 0:
        response_message['message'] = "All products are duplicates"
        _logger.info("All %d products are duplicates", len(skipped_products))
        status = 207
    elif skipped_products:
        response_message['message'] = f"Uploaded {created_count} products, skipped {len(skipped_products)} duplicates"
        _logger.info("Uploaded %d products, skipped %d duplicates", created_count, len(skipped_products))
        status = 207
    else:
        response_message['message'] = f"Successfully uploaded {created_count} products with initial stock"
        _logger.info("Successfully uploaded %d products with initial stock", created_count)
        status = 200

    return http.Response(
        json.dumps(response_message),
        status=status,
        content_type='application/json'
    )


def handle_error(error, status_code=400):
    _logger.error("Error: %s", str(error))
    error_message = "An error occurred" if status_code == 500 else str(error)
    return http.Response(
        json.dumps({'error': error_message}),
        status=status_code,
        content_type='application/json'
    )


def build_response_update_stock(updated_products, failed_products, response_time_ms):
    response_data = {
        'updated': len(updated_products),
        'updated_products': updated_products,
        'failed': failed_products,
        'response_time_ms': response_time_ms,
        'message': (f"Successfully updated {len(updated_products)} products"
                    if updated_products and not failed_products else
                    "Partially updated products" if updated_products else
                    "Failed to update products")
    }
    return Response(
        json.dumps(response_data),
        content_type='application/json',
        status=200 if updated_products and not failed_products else 207 if updated_products else 400
    )


def build_response_create_invoice(invoice_id, invoice_number, response_time_ms, message=None, extra_fields=None):
    if not isinstance(invoice_id, int):
        raise ValueError("Invoice ID must be an integer")
    if not isinstance(invoice_number, str) or not invoice_number:
        raise ValueError("Invoice number must be a non-empty string")
    if not isinstance(response_time_ms, (int, float)) or response_time_ms < 0:
        raise ValueError("Response time must be a non-negative number")

    response = {
        'invoice_id': invoice_id,
        'invoice_number': invoice_number,
        'response_time_ms': round(response_time_ms, 3),
        'message': message if message else f"Invoice {invoice_number} created successfully"
    }

    if extra_fields and isinstance(extra_fields, dict):
        response.update(extra_fields)

    json_response = json.dumps(response)

    return Response(json_response, content_type='application/json', status=200)


def make_json_response(payload, status=200):
    return Response(
        json.dumps({'status': status, 'success': status < 400, 'data': payload if status < 400 else None,
                    'error': payload if status >= 400 else None}),
        status=status,
        content_type='application/json'
    )


def compute_etag(data):
    return sha256(json.dumps(data, default=str, sort_keys=True).encode()).hexdigest()
