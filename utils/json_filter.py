import json
import logging

_logger = logging.getLogger(__name__)

ALLOWED_FILTER_FIELDS = [
    'id', 'name', 'default_code', 'list_price', 'qty_available', 'categ_id', 'categ_id.name'
]

ALLOWED_STOCK_FILTER_FIELDS = [
    'product_id', 'location_id', 'quantity', 'reserved_quantity', 'inventory_quantity'
]


def parse_filter_param(param):
    try:
        data = json.loads(param)
        if not isinstance(data, dict):
            raise ValueError("filter must be a JSON object")

        domain = []

        for field, condition in data.items():
            if field not in ALLOWED_FILTER_FIELDS:
                raise ValueError(f"Field not allowed in filter: {field}")

            if isinstance(condition, list) and len(condition) == 2:
                operator, value = condition
                domain.append((field, operator, value))
            else:
                domain.append((field, '=', condition))

        return domain

    except Exception as e:
        _logger.warning("Invalid filter: %s", str(e))
        raise ValueError(f"Invalid filter format: {str(e)}")


def parse_stock_filter_param(param):
    try:
        data = json.loads(param)
        if not isinstance(data, dict):
            raise ValueError("filter must be a JSON object")

        domain = []
        for field, condition in data.items():
            if field not in ALLOWED_STOCK_FILTER_FIELDS:
                raise ValueError(f"Field not allowed in stock filter: {field}")

            if isinstance(condition, list) and len(condition) == 2:
                operator, value = condition
                domain.append((field, operator, value))
            else:
                domain.append((field, '=', condition))
        return domain

    except Exception as e:
        _logger.warning("Invalid stock filter: %s", str(e))
        raise ValueError(f"Invalid stock filter format: {str(e)}")
