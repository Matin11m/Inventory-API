from datetime import datetime


def format_sale_record(record):
    return {
        'id': record.get('id'),
        'name': record.get('name'),
        'partner': record.get('partner_id')[1] if record.get('partner_id') else None,
        'date_order': record.get('date_order').strftime('%Y-%m-%d')
        if isinstance(record.get('date_order'), datetime)
        else str(record.get('date_order'))[:10] if record.get('date_order') else None,
        'state': record.get('state'),
        'amount_total': record.get('amount_total'),
    }
