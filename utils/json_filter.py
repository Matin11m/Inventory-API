import json
import logging

_logger = logging.getLogger(__name__)

ALLOWED_FILTER_FIELDS = [
    'id', 'name', 'default_code', 'list_price', 'qty_available', 'categ_id', 'categ_id.name'
]

ALLOWED_STOCK_FILTER_FIELDS = [
    'product_id', 'location_id', 'quantity', 'reserved_quantity', 'inventory_quantity'
]

ALLOWED_CUSTOMER_FILTER_FIELDS = ['id', 'name', 'email', 'phone', 'street']
ALLOWED_OPERATORS = ['=', '!=', 'ilike', 'like', '>', '<', '>=', '<=', 'in', 'not in']


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


def parse_customer_filter_param(param):
    try:
        data = json.loads(param)
        if not isinstance(data, dict):
            raise ValueError("Filter must be a JSON object")
        domain = []
        for field, condition in data.items():
            if field not in ALLOWED_CUSTOMER_FILTER_FIELDS:
                raise ValueError(f"Field not allowed in customer filter: {field}")
            if isinstance(condition, list) and len(condition) == 2:
                operator, value = condition
                if operator not in ALLOWED_OPERATORS:
                    raise ValueError(f"Invalid operator in customer filter: {operator}")
                domain.append((field, operator, value))
            else:
                domain.append((field, '=', condition))
        return domain
    except json.JSONDecodeError:
        _logger.warning("Invalid JSON format in filter")
        raise ValueError("Invalid JSON format in filter")
    except Exception as e:
        _logger.warning("Invalid customer filter: %s", str(e))
        raise ValueError(f"Invalid customer filter format: {str(e)}")
