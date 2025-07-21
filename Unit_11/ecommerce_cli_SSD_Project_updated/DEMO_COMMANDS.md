# Demo Commands

# Welcome to the demonstration of my implementation of the Command-Line E-Commerce Application (REVISED / Second Attempt after feedback).

## E-Commerce Workflow Demo

### 1. User Registration & Login
```bash
python run.py register --username "customer774" --password "CustomerPass123!"
python run.py login --username "customer774" --password "CustomerPass123!"
```

### 2. Browse Products
```bash
python run.py list-products
```

### 3. Add Items to Cart
```bash
python run.py add-to-cart --product_id "03a3250b-3be7-45d8-b78c-b9cd25ee3f1d" --quantity 1
python run.py add-to-cart --product_id "c05e1e1f-d629-45c1-98a7-ae3edf5970d4" --quantity 2
```

### 4. View Cart & Checkout
```bash
python run.py view-cart
python run.py checkout
python run.py set-shipping-address --street "123 Oxford Street" --city "London" --state "England" --zip_code "W1D 1BS" --country "UK"
python run.py set-payment-method --payment_method credit_card
```

### 5. View Orders & Logout
```bash
python run.py my-orders
python run.py logout
```

## Admin Security Commands Demo

### 1. Admin Login
```bash
python run.py login --username admin --password AdminPass123!
```

### 2. Session Management (A01)
```bash
python run.py list-sessions --username admin --password AdminPass123!
python run.py cleanup-sessions --username admin --password AdminPass123!
```

### 3. Rate Limiting (A07)
```bash
python run.py login --username customer298 --password WrongPass123!
python run.py rate-limit-stats --username admin --password AdminPass123!
python run.py unlock-account --username admin --password AdminPass123!
```

### 4. Cryptographic Key Management (A02)
```bash
python run.py rotate-keys --username admin --password AdminPass123!
python run.py validate-keys --username admin --password AdminPass123!
```

### 5. Data Integrity (A08)
```bash
python run.py check-integrity --username admin --password AdminPass123!
```

### 6. Threat Modeling (A04)
```bash
python run.py analyze-threats --username admin --password AdminPass123!
```

### 7. Vulnerability Scanning (A06)
```bash
python run.py scan-vulnerabilities --username admin --password AdminPass123!
python run.py check-advisories --username admin --password AdminPass123!
```

### 8. Security Reporting (A09)
```bash
python run.py security-report --username admin --password AdminPass123!
python run.py validate-logs --username admin --password AdminPass123!
```

### 9. SSRF Protection (A10)
```bash
python run.py test-url-validation --username admin --password AdminPass123!
```

## Product Management Commands

### List Products
```bash
python run.py list-products
```

### Add Product
```bash
python run.py add-product --name "Lenovo IdeaPad 3" --price 399.99 --stock 75 --description "Lenovo IdeaPad 3 15-inch AMD Ryzen 5 8GB RAM 256GB SSD"
python run.py add-product --name "iPad Air 5th Gen" --price 599.99 --stock 60 --description "Apple iPad Air 5th Generation 10.9-inch M1 Chip 64GB WiFi"
python run.py add-product --name "Dell XPS 13" --price 999.99 --stock 30 --description "Dell XPS 13 13.4-inch Intel i7 16GB RAM 512GB SSD InfinityEdge Display"
```

### Update Product
```bash
python run.py update-product --product_id "8bef5d47-2a4f-4e70-a1c3-df3ea4af2d27" --name "HP EliteBook 7102x Pro" --price 129.99 --stock 75 --description "HP EliteBook 7102x Pro Touchscreen Laptop 16GB 512GB SSD - Updated Model"
```

### Delete Product
```bash
python run.py delete-product --product_id ""
```

## Shopping Cart Operations

### Add to Cart
```bash
python run.py add-to-cart --product_id "03a3250b-3be7-45d8-b78c-b9cd25ee3f1d" --quantity 2
```

### View Cart
```bash
python run.py view-cart
```

### Remove from Cart
```bash
python run.py remove-from-cart --product_id "03a3250b-3be7-45d8-b78c-b9cd25ee3f1d"
```

## Order Management

### Checkout
```bash
python run.py checkout
```

### View Orders
```bash
python run.py my-orders
```

## Authentication

### Register
```bash
python run.py register --username "newuser" --password "SecurePass123!"
```

### Login
```bash
python run.py login --username "newuser" --password "SecurePass123!"
```

### Logout
```bash
python run.py logout
``` 