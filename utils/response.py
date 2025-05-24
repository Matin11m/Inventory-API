import json
import logging
from odoo import http

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
    elif skipped_products:
        response_message['message'] = f"Uploaded {created_count} products, skipped {len(skipped_products)} duplicates"
        _logger.info("Uploaded %d products, skipped %d duplicates", created_count, len(skipped_products))
    else:
        response_message['message'] = f"Successfully uploaded {created_count} products with initial stock"
        _logger.info("Successfully uploaded %d products with initial stock", created_count)

    return http.Response(
        json.dumps(response_message),
        status=200,
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