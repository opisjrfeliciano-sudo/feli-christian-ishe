<?php
session_start();
require_once '../db.php';

$action = $_GET['action'] ?? '';
if (!$action && $_SERVER['REQUEST_METHOD'] !== 'GET') {
    $data = json_decode(file_get_contents('php://input'), true);
    $action = $data['action'] ?? '';
}

switch ($action) {
    case 'login':
        handleLogin();
        break;
    case 'logout':
        handleLogout();
        break;
    case 'signup':
        handleSignup();
        break;
    case 'add_product':
        handleAddProduct();
        break;
    case 'list_products':
        handleListProducts();
        break;
    case 'update_product':
        handleUpdateProduct();
        break;
    case 'delete_product':
        handleDeleteProduct();
        break;
    case 'add_movement':
        handleAddMovement();
        break;
    case 'list_movements':
        handleListMovements();
        break;
    default:
        json_response(false, 'Invalid action', null, 400);
}

function handleLogin() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        json_response(false, 'Method not allowed', null, 405);
    }

    $data = json_decode(file_get_contents('php://input'), true);
    $username = trim($data['username'] ?? '');
    $password = $data['password'] ?? '';

    if (!$username || !$password) {
        json_response(false, 'Username and password required', null, 400);
    }

    try {
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            json_response(true, 'Login successful', ['user' => $user['username']]);
        } else {
            json_response(false, 'Invalid username or password', null, 401);
        }
    } catch (PDOException $e) {
        json_response(false, 'Login failed: ' . $e->getMessage(), null, 500);
    }
}

function handleLogout() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        json_response(false, 'Method not allowed', null, 405);
    }

    session_destroy();
    json_response(true, 'Logged out successfully');
}

function handleSignup() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        json_response(false, 'Method not allowed', null, 405);
    }

    $data = json_decode(file_get_contents('php://input'), true);

    $fname    = trim($data['fname']    ?? '');
    $lname    = trim($data['lname']    ?? '');
    $bdate    = $data['bdate']         ?? '';
    $gender   = $data['gender']        ?? '';
    $gmail    = trim($data['gmail']    ?? '');
    $contact  = trim($data['contact']  ?? '');
    $username = trim($data['username'] ?? '');
    $password = $data['password']      ?? '';

    $validCats = ['Male','Female','Prefer not to say'];
    $errors = [];

    if (!$fname) $errors[] = 'First name is required.';
    if (!$lname) $errors[] = 'Last name is required.';
    if (!$bdate) $errors[] = 'Birthdate is required.';
    if (!in_array($gender, $validCats, true)) $errors[] = 'Invalid gender.';
    if (!filter_var($gmail, FILTER_VALIDATE_EMAIL)) $errors[] = 'Invalid email.';
    if (!$contact) $errors[] = 'Contact is required.';
    if (!$username) $errors[] = 'Username is required.';
    if (strlen($password) < 8) $errors[] = 'Password must be at least 8 characters.';

    if (!empty($errors)) {
        json_response(false, 'Validation failed', ['errors' => $errors], 400);
    }

    try {
        $hashed = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare(
            "INSERT INTO users (fname, lname, bdate, gender, gmail, contact, username, password)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([$fname, $lname, $bdate, $gender, $gmail, $contact, $username, $hashed]);

        json_response(true, 'Account created successfully', null, 201);
    } catch (PDOException $e) {
        if (strpos($e->getMessage(), 'Duplicate') !== false) {
            json_response(false, 'Username or email already exists', null, 409);
        }
        json_response(false, 'Failed to create account: ' . $e->getMessage(), null, 500);
    }
}

function handleAddProduct() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        json_response(false, 'Method not allowed', null, 405);
    }

    if (!isset($_SESSION['user_id'])) {
        json_response(false, 'Unauthorized', null, 401);
    }

    $data = json_decode(file_get_contents('php://input'), true);

    $name     = trim($data['name'] ?? '');
    $category = trim($data['category'] ?? '');
    $qty      = (int)($data['qty'] ?? 0);
    $price    = (float)($data['price'] ?? 0);

    $validCats = ['Food','Drinks','Snacks','Fruits','Vegetables','Meat','Dairy','Bakery','Frozen','Seafood'];
    $errors = [];

    if (!$name) $errors[] = 'Product name is required.';
    if ($qty < 1) $errors[] = 'Quantity must be at least 1.';
    if ($price < 0) $errors[] = 'Price cannot be negative.';
    if (!in_array($category, $validCats, true)) $errors[] = 'Invalid category.';

    if (!empty($errors)) {
        json_response(false, 'Validation failed', ['errors' => $errors], 400);
    }

    try {
        $user_id = $_SESSION['user_id'];
        $stmt = $conn->prepare("INSERT INTO products (user_id, name, category, qty, price) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$user_id, $name, $category, $qty, $price]);

        json_response(true, 'Product added successfully', ['id' => $conn->lastInsertId()], 201);
    } catch (PDOException $e) {
        json_response(false, 'Failed to add product: ' . $e->getMessage(), null, 500);
    }
}

function handleListProducts() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        json_response(false, 'Method not allowed', null, 405);
    }

    if (!isset($_SESSION['user_id'])) {
        json_response(false, 'Unauthorized', null, 401);
    }

    try {
        $user_id = $_SESSION['user_id'];
        $stmt = $conn->prepare("SELECT * FROM products WHERE user_id = ? ORDER BY name ASC");
        $stmt->execute([$user_id]);
        $products = $stmt->fetchAll(PDO::FETCH_ASSOC);

        json_response(true, 'Products retrieved', ['products' => $products]);
    } catch (PDOException $e) {
        json_response(false, 'Failed to retrieve products: ' . $e->getMessage(), null, 500);
    }
}

function handleUpdateProduct() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        json_response(false, 'Method not allowed', null, 405);
    }

    if (!isset($_SESSION['user_id'])) {
        json_response(false, 'Unauthorized', null, 401);
    }

    $data = json_decode(file_get_contents('php://input'), true);

    $id     = (int)($data['id'] ?? 0);
    $action = trim($data['action'] ?? '');
    $value  = $data['value'] ?? null;

    if ($id <= 0 || !$action) {
        json_response(false, 'Invalid parameters', null, 400);
    }

    $user_id = $_SESSION['user_id'];

    $verify = $conn->prepare("SELECT id FROM products WHERE id = ? AND user_id = ?");
    $verify->execute([$id, $user_id]);
    if (!$verify->fetch()) {
        json_response(false, 'Product not found', null, 404);
    }

    try {
        switch ($action) {
            case 'qty':
                $newQty = (int)$value;
                if ($newQty < 1) {
                    json_response(false, 'Quantity must be at least 1', null, 400);
                }
                $stmt = $conn->prepare("UPDATE products SET qty = ? WHERE id = ? AND user_id = ?");
                $stmt->execute([$newQty, $id, $user_id]);
                break;

            case 'price':
                $newPrice = (float)$value;
                if ($newPrice < 0) {
                    json_response(false, 'Price cannot be negative', null, 400);
                }
                $stmt = $conn->prepare("UPDATE products SET price = ? WHERE id = ? AND user_id = ?");
                $stmt->execute([$newPrice, $id, $user_id]);
                break;

            case 'increase':
                $stmt = $conn->prepare("UPDATE products SET qty = qty + 1 WHERE id = ? AND user_id = ?");
                $stmt->execute([$id, $user_id]);
                break;

            case 'decrease':
                $stmt = $conn->prepare("UPDATE products SET qty = GREATEST(1, qty - 1) WHERE id = ? AND user_id = ?");
                $stmt->execute([$id, $user_id]);
                break;

            default:
                json_response(false, 'Invalid action', null, 400);
        }

        json_response(true, 'Product updated successfully');
    } catch (PDOException $e) {
        json_response(false, 'Failed to update product: ' . $e->getMessage(), null, 500);
    }
}

function handleDeleteProduct() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        json_response(false, 'Method not allowed', null, 405);
    }

    if (!isset($_SESSION['user_id'])) {
        json_response(false, 'Unauthorized', null, 401);
    }

    $data = json_decode(file_get_contents('php://input'), true);

    $id = (int)($data['id'] ?? 0);

    if ($id <= 0) {
        json_response(false, 'Invalid product ID', null, 400);
    }

    try {
        $user_id = $_SESSION['user_id'];
        $stmt = $conn->prepare("DELETE FROM products WHERE id = ? AND user_id = ?");
        $stmt->execute([$id, $user_id]);

        if ($stmt->rowCount() > 0) {
            json_response(true, 'Product deleted successfully');
        } else {
            json_response(false, 'Product not found', null, 404);
        }
    } catch (PDOException $e) {
        json_response(false, 'Failed to delete product: ' . $e->getMessage(), null, 500);
    }
}

function handleAddMovement() {
    global $conn;

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        json_response(false, 'Method not allowed', null, 405);
    }

    if (!isset($_SESSION['user_id'])) {
        json_response(false, 'Unauthorized', null, 401);
    }

    $data = json_decode(file_get_contents('php://input'), true);

    $product_id = (int)($data['product_id'] ?? 0);
    $movement_type = trim($data['movement_type'] ?? '');
    $quantity_change = (int)($data['quantity_change'] ?? 0);
    $reference_num = trim($data['reference_num'] ?? '');
    $notes = trim($data['notes'] ?? '');

    $validTypes = ['purchase', 'sale', 'adjustment', 'damage', 'return'];
    $errors = [];

    if ($product_id <= 0) $errors[] = 'Product ID is required.';
    if (!in_array($movement_type, $validTypes, true)) $errors[] = 'Invalid movement type.';
    if ($quantity_change == 0) $errors[] = 'Quantity change is required.';

    if (!empty($errors)) {
        json_response(false, 'Validation failed', ['errors' => $errors], 400);
    }

    try {
        $user_id = $_SESSION['user_id'];

        $verify = $conn->prepare("SELECT id, qty FROM products WHERE id = ? AND user_id = ?");
        $verify->execute([$product_id, $user_id]);
        $product = $verify->fetch(PDO::FETCH_ASSOC);

        if (!$product) {
            json_response(false, 'Product not found', null, 404);
        }

        $new_qty = max(0, $product['qty'] + $quantity_change);

        $stmt = $conn->prepare(
            "INSERT INTO stock_movements (product_id, user_id, movement_type, quantity_change, reference_num, notes)
             VALUES (?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([$product_id, $user_id, $movement_type, $quantity_change, $reference_num, $notes]);

        $update = $conn->prepare("UPDATE products SET qty = ? WHERE id = ?");
        $update->execute([$new_qty, $product_id]);

        json_response(true, 'Stock movement recorded', ['new_qty' => $new_qty], 201);
    } catch (PDOException $e) {
        json_response(false, 'Failed to record movement: ' . $e->getMessage(), null, 500);
    }
}

function handleListMovements() {
    global $conn;

    if (!isset($_SESSION['user_id'])) {
        json_response(false, 'Unauthorized', null, 401);
    }

    try {
        $user_id = $_SESSION['user_id'];
        $product_id = $_GET['product_id'] ?? null;

        $query = "SELECT sm.*, p.name as product_name, p.category
                  FROM stock_movements sm
                  JOIN products p ON sm.product_id = p.id
                  WHERE sm.user_id = ?";
        $params = [$user_id];

        if ($product_id) {
            $query .= " AND sm.product_id = ?";
            $params[] = $product_id;
        }

        $query .= " ORDER BY sm.created_at DESC LIMIT 100";

        $stmt = $conn->prepare($query);
        $stmt->execute($params);
        $movements = $stmt->fetchAll(PDO::FETCH_ASSOC);

        json_response(true, 'Stock movements retrieved', ['movements' => $movements]);
    } catch (PDOException $e) {
        json_response(false, 'Failed to retrieve movements: ' . $e->getMessage(), null, 500);
    }
}
?>
