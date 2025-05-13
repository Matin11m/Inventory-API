# Inventory API

The **Inventory API** module provides a secure **REST API** to access product and stock data in Odoo. This module allows third-party applications to interact with Odoo's product and stock information using a set of well-defined endpoints. It ensures data security through **JWT-based authentication** and offers advanced features like rate limiting, flexible filtering, dynamic field selection, **caching**, and **role-based access control (RBAC)**.

## Features

- **JWT-based authentication** for secure access to the API.
- **Rate limiting** to prevent abuse and DDoS attacks.
- **Pagination** and flexible **filtering** for retrieving data.
- **Dynamic field selection** for tailored API responses.
- **CRUD operations** on inventory-related data.
- Seamless integration with Odoo's **stock** and **product** modules.
- **Export products and stock data** to CSV format.
- **System Monitoring** with real-time logging of API requests.
- **Caching** of frequently requested data to improve performance.
- **Role-Based Access Control (RBAC)** for managing permissions and access rights based on user roles.

---

## Installation

### Prerequisites:

- Odoo 17.0 installed.
- PostgreSQL database configured and accessible.
- Python libraries **`requests`** and **`pyjwt`** installed.

### Steps to Install:

1. Clone the repository to your Odoo **custom addons** directory.
2. Add the path to your `odoo.conf` file in the **`addons_path`**:

    ```ini
    [options]
    addons_path = /path/to/odoo/addons,/path/to/custom/addons
    ```

3. Update your Odoo apps list from the Odoo interface.
4. Install the **Inventory API** module from the Odoo interface.

---

## Example API Requests

### 1. Login (JWT Authentication)

- **Endpoint**: `/api/login`
- **Method**: POST
- **Body**:

    ```json
    {
      "username": "testuser",
      "password": "password123"
    }
    ```

- **Response**:

    ```json
    {
      "token": "your_jwt_token_here"
    }
    ```

---

### 2. Get Products

- **Endpoint**: `/api/products`
- **Method**: GET
- **Parameters**:

    ```json
    {
      "limit": "(optional) Number of items per page.",
      "offset": "(optional) The page number.",
      "fields": "(optional) Comma-separated fields to include in the response."
    }
    ```

- **Response**:

    ```json
    {
      "status": "success",
      "data": [
        {
          "id": 1,
          "name": "Product A",
          "list_price": 100,
          "qty_available": 50
        }
      ],
      "pagination": {
        "limit": 10,
        "offset": 0,
        "total": 50
      }
    }
    ```

---

### 3. Get Stock Information

- **Endpoint**: `/api/stock`
- **Method**: GET
- **Parameters**:
    - `location_id`: *(optional)* The ID of the stock location to filter by.

- **Response**:

    ```json
    {
      "status": "success",
      "data": [
        {
          "product_id": 1,
          "location_id": 1,
          "quantity": 100
        }
      ]
    }
    ```

---

### 4. Export Data

- **Endpoint**: `/api/products/export`
- **Method**: GET
- **Parameters**:
    - `limit`: *(optional)* The number of products to export.
    - `fields`: *(optional)* Comma-separated fields to include in the export.

- **Response**: CSV file

    ```csv
    id,name,default_code,list_price,qty_available
    1,Product A,PA123,100,50
    2,Product B,PB123,150,30
    ```

---

## **Security**

This module uses **JWT (JSON Web Tokens)** for securing access to the API. You need to authenticate using a valid JWT token that can be obtained by logging in with valid credentials.

**Secret key** is defined in your `odoo.conf` file:

```ini
jwt_secret_key = YOUR_SECRET_KEY_HERE

You can generate a secret_key using a secure random string generator or by using the Python secrets library:
```ini
import secrets
print(secrets.token_urlsafe(64))  # Generates a 64-byte random key
```
---

Caching

This module implements caching to store frequently requested data and reduce the load on the database. Caching helps improve the performance of the API by storing the results of database queries for a specified period.

Caching Strategy:

    Frequently accessed data, such as product lists or stock information, is cached.

    Cache invalidation occurs when there is a change in the underlying data, ensuring that stale data is not served.



Cache Invalidation:

For example, when a product's price or quantity is updated, the cache for that product will be invalidated, and a fresh value will be fetched from the database.


System Monitoring

This module includes real-time monitoring of API requests. All API requests are logged with detailed information, such as:

    User making the request.

    API endpoint accessed.

    IP address of the client making the request.

    HTTP method (GET, POST, PUT, DELETE).

    Parameters sent in the request.

    Response status and response time in milliseconds.

These logs can be accessed through the Odoo backend by navigating to the API Log menu.

API Logs in Odoo:

You can monitor and view the logs of API requests in the Odoo interface under the API Log section. This allows you to trace activities and ensure that the API is functioning as expected.


Role-Based Access Control (RBAC)

The module includes Role-Based Access Control (RBAC), which allows you to define fine-grained permissions based on user roles. This ensures that only authorized users can access specific data or perform certain actions.


Role Permissions:

    Admins have full access to all endpoints and operations.

    Stock Managers can view and manage stock-related data.

    Product Managers can access product information and perform CRUD operations.

The access permissions are defined in the ir.model.access.csv file, which controls which models and operations are accessible by specific user groups.



License

This module is licensed under the AGPL-3 license.

Contributing

Feel free to fork the repository, contribute improvements, or report issues. All contributions are welcome.

Maintainer

    Matin Shahmaleki

    Email: matin.shahmaleki001@gmail.com

    Website: https://www.linkedin.com/in/matin-shahmaleki

