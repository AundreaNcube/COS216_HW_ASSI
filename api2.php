<?php
/*
Amantle Keamogetse Temo u23539764
*/

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Content-Type: application/json');

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

require_once __DIR__ . "/COS216/HA/PHP/config.php";

class Database
{
    private static $instance = null;
    private $conn;

    private function __construct()
    {
        try {
            $db = ConnectToDatabase::getInstance();
            $this->conn = $db->getConnection();
            if (!$this->conn || $this->conn->connect_errno) {
                throw new Exception("Database connection failed");
            }
        } catch (Exception $e) {
            error_log("Database connection error: " . $e->getMessage());
            throw $e;
        }
    }

    public static function getInstance()
    {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getConnection()
    {
        if (!$this->conn->ping()) {
            $this->conn->close();
            $db = ConnectToDatabase::getInstance();
            $this->conn = $db->getConnection();
        }
        return $this->conn;
    }
}

class HandleRequest
{
    public function handleRequest()
    {
        try {
            $rawInput = file_get_contents('php://input');
            $requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN';
            error_log("========= NEW REQUEST =========");
            error_log("Request Method: " . $requestMethod);
            if ($requestMethod === 'OPTIONS') {
                $this->sendResponse(200, []);
                return;
            }
            if ($requestMethod !== 'POST') {
                throw new Exception("Only POST requests are allowed", 405);
            }
            $input = $this->parseInput($rawInput);
            $this->type_of_Request($input);
        } catch (Exception $e) {
            $this->sendErrorResponse($e);
        }
    }

    private function parseInput($json)
    {
        if (empty($json)) {
            throw new Exception("No data received", 400);
        }
        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Invalid JSON format: " . json_last_error_msg(), 400);
        }
        return $data;
    }

    private function type_of_Request($input)
    {
        if (!isset($input['type'])) {
            throw new Exception("Missing request type", 400);
        }
        switch ($input['type']) {
            case 'Register':
                $handler = new Register();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'Login':
                $handler = new Login();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'GetAllProducts':
                $handler = new Products();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'GetUserInfo':
                $handler = new GetUserInfo();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'CreateOrder':
                $handler = new CreateOrder();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'UpdateOrder':
                $handler = new UpdateOrder();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'GetAllOrders':
                $handler = new GetAllOrders();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            default:
                throw new Exception("Invalid request type", 400);
        }
    }

    private function sendErrorResponse(Exception $e)
    {
        $code = $e->getCode() ?: 400;
        $this->sendResponse($code, [
            'status' => 'error',
            'timestamp' => round(microtime(true) * 1000),
            'data' => $e->getMessage()
        ]);
    }

    private function sendResponse($code, $data)
    {
        http_response_code($code);
        echo json_encode($data);
        exit();
    }
}

class Register
{
    private const valid_usertypes = ['Customer', 'Courier', 'Inventory Manager', 'Distributor'];

    public function process($data)
    {
        $this->validate($data);
        return $this->registerUser($data);
    }

    private function validate($data)
    {
        $required = ['type', 'name', 'surname', 'email', 'password', 'user_type'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new Exception("Field '$field' is required", 400);
            }
        }
        if (!preg_match('/^[a-zA-Z\s\-]+$/', $data['name'])) {
            throw new Exception("Name cannot contain numbers or special characters", 400);
        }
        if (!preg_match('/^[a-zA-Z\s\-]+$/', $data['surname'])) {
            throw new Exception("Surname cannot contain numbers or special characters", 400);
        }
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            throw new Exception("Invalid email format", 400);
        }
        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/', $data['password'])) {
            throw new Exception("Password must contain uppercase, lowercase, number, and special character", 400);
        }
        if (!in_array($data['user_type'], self::valid_usertypes)) {
            throw new Exception("Invalid user type", 400);
        }
    }

    private function registerUser($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $data['email']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            throw new Exception("Email already registered", 409);
        }
        $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
        $apiKey = bin2hex(random_bytes(32));
        $stmt = $conn->prepare("INSERT INTO users (name, surname, email, password, user_type, api_key) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bind_param(
            "ssssss",
            $data['name'],
            $data['surname'],
            $data['email'],
            $hashedPassword,
            $data['user_type'],
            $apiKey
        );
        if (!$stmt->execute()) {
            error_log("Registration failed: " . $stmt->error);
            throw new Exception("Registration failed", 500);
        }
        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => ['apikey' => $apiKey]
        ];
    }
}

class Login
{
    public function process($data)
    {
        $this->validate($data);
        return $this->authenticateUser($data);
    }

    private function validate($data)
    {
        $required = ['type', 'email', 'password'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new Exception("Field '$field' is required", 400);
            }
        }
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            throw new Exception("Invalid email format", 400);
        }
    }

    private function authenticateUser($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();
        $stmt = $conn->prepare("SELECT id, name, surname, email, password, api_key, user_type FROM users WHERE email = ?");
        $stmt->bind_param("s", $data['email']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("User not found", 404);
        }
        $user = $result->fetch_assoc();
        if (!password_verify($data['password'], $user['password'])) {
            throw new Exception("Invalid password", 401);
        }
        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => [
                'name' => $user['name'],
                'surname' => $user['surname'],
                'apikey' => $user['api_key'],
                'user_type' => $user['user_type']
            ]
        ];
    }
}

class Products
{
    private const product_fields = [
        'id',
        'title',
        'brand',
        'image_url',
        'categories',
        'dimensions',
        'is_available',
        'distributor'
    ];

    public function process($data)
    {
        $this->validate($data);
        $products = $this->getProducts($data);
        $products = $this->formatProducts($products, $data['return']);
        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => $products
        ];
    }

    private function validate($data)
    {
        $required = ['apikey', 'type', 'return'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new Exception("Field '$field' is required", 400);
            }
        }
        $db = Database::getInstance();
        $conn = $db->getConnection();
        $stmt = $conn->prepare("SELECT id FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $data['apikey']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows === 0) {
            throw new Exception("Invalid API key", 401);
        }
        if ($data['return'] !== '*' && !is_array($data['return'])) {
            throw new Exception("Return parameter must be '*' or an array of fields", 400);
        }
        if (is_array($data['return'])) {
            $invalidFields = array_diff($data['return'], self::product_fields);
            if (!empty($invalidFields)) {
                throw new Exception("Invalid return field(s): " . implode(', ', $invalidFields), 400);
            }
        }
        if (isset($data['limit']) && (!is_numeric($data['limit']) || $data['limit'] <= 0)) {
            throw new Exception("Limit must be a positive number", 400);
        }
        if (isset($data['search']) && is_array($data['search'])) {
            $allowedSearchFields = ['id', 'title', 'brand', 'categories', 'dimensions', 'is_available'];
            foreach ($data['search'] as $column => $value) {
                if (!in_array($column, $allowedSearchFields)) {
                    throw new Exception("Invalid search field: '$column'", 400);
                }
            }
        }
    }

    private function getProducts($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();
        $fields = $data['return'];
        $limit = isset($data['limit']) ? min(max(intval($data['limit']), 1), 500) : 100;
        $sort = $data['sort'] ?? null;
        $order = isset($data['order']) ? strtoupper($data['order']) : 'ASC';
        $search = $data['search'] ?? [];
        $fuzzy = $data['fuzzy'] ?? true;

        $selectClause = $this->buildSelectClause($fields);
        $query = "SELECT $selectClause FROM products WHERE 1=1";
        list($query, $params, $types) = $this->addSearchConditions($query, $search, $fuzzy);
        $query = $this->addSorting($query, $sort, $order);
        list($query, $params, $types) = $this->addLimit($query, $params, $types, $limit);

        $stmt = $conn->prepare($query);
        if (!$stmt) {
            error_log("Prepare failed: " . $conn->error);
            throw new Exception("Database error", 500);
        }
        if (!empty($types)) {
            $stmt->bind_param($types, ...$params);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_all(MYSQLI_ASSOC);
    }

    private function formatProducts($products, $returnFields)
    {
        $fields = $returnFields === '*' ? self::product_fields : $returnFields;
        $filteredProducts = [];

        foreach ($products as $product) {
            if (in_array('categories', $fields) && !empty($product['categories'])) {
                $decoded = json_decode($product['categories'], true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    $product['categories'] = $decoded;
                }
            }

            $filteredProduct = [];
            foreach ($fields as $field) {
                if ($field === '*' || array_key_exists($field, $product)) {
                    $filteredProduct[$field] = $product[$field];
                }
            }
            $filteredProducts[] = $filteredProduct;
        }

        return $filteredProducts;
    }

    private function buildSelectClause($fields)
    {
        if ($fields === '*' || !is_array($fields)) {
            return '*';
        }
        $safeFields = array_intersect($fields, self::product_fields);
        return empty($safeFields) ? '*' : implode(', ', $safeFields);
    }

    private function addSearchConditions($query, $search, $fuzzy)
    {
        $params = [];
        $types = "";
        foreach ($search as $column => $value) {
            if (!in_array($column, self::product_fields)) {
                continue;
            }
            switch ($column) {
                case 'title':
                case 'brand':
                case 'image_url':
                case 'dimensions':
                    if ($fuzzy) {
                        $query .= " AND $column LIKE ?";
                        $params[] = "%$value%";
                    } else {
                        $query .= " AND $column = ?";
                        $params[] = $value;
                    }
                    $types .= "s";
                    break;
                case 'categories':
                    $query .= " AND JSON_CONTAINS(categories, ?)";
                    $params[] = json_encode($value);
                    $types .= "s";
                    break;
                case 'is_available':
                    $query .= " AND is_available = ?";
                    $params[] = $value ? 1 : 0;
                    $types .= "i";
                    break;
                case 'distributor':
                    $query .= " AND distributor = ?";
                    $params[] = $value;
                    $types .= "i";
                    break;
            }
        }
        return [$query, $params, $types];
    }

    private function addSorting($query, $sort, $order)
    {
        $allowedSortFields = ['id', 'title', 'brand', 'distributor'];
        if ($sort && in_array($sort, $allowedSortFields)) {
            $order = ($order === 'DESC') ? 'DESC' : 'ASC';
            $query .= " ORDER BY $sort $order";
        }
        return $query;
    }

    private function addLimit($query, $params, $types, $limit)
    {
        $query .= " LIMIT ?";
        $params[] = $limit;
        $types .= "i";
        return [$query, $params, $types];
    }
}

class GetUserInfo
{
    public function process($data)
    {
        $this->validate($data);
        return $this->getInfo($data);
    }

    private function validate($data)
    {
        $required = ['apikey', 'type'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new Exception("Field '$field' is required", 400);
            }
        }
    }

    private function getInfo($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();
        $stmt = $conn->prepare("SELECT name, surname FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $data['apikey']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("Invalid API key", 401);
        }
        $user = $result->fetch_assoc();
        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => [
                'name' => $user['name'],
                'surname' => $user['surname']
            ]
        ];
    }
}

class CreateOrder
{
    public function __construct() {}

    public function process($data)
    {
        $data = $this->validate($data);
        return $this->createOrder($data);
    }

    private function validate($data)
    {
        $required = ['apikey', 'type', 'destination_latitude', 'destination_longitude', 'products'];
        foreach ($required as $field) {
            if (!isset($data[$field]) || empty($data[$field])) {
                throw new Exception("Field '$field' is required", 400);
            }
        }

        $db = Database::getInstance();
        $conn = $db->getConnection();
        $stmt = $conn->prepare("SELECT id, user_type FROM users WHERE api_key = ?");
        if (!$stmt) {
            error_log("Prepare failed for API key validation: " . $conn->error);
            throw new Exception("Database error: Failed to validate API key", 500);
        }
        $stmt->bind_param("s", $data['apikey']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("Invalid API key", 401);
        }
        $user = $result->fetch_assoc();
        if ($user['user_type'] !== 'Customer') {
            throw new Exception("Only Customers can create orders", 403);
        }
        $data['customer_id'] = $user['id'];

        if (!is_numeric($data['destination_latitude']) || $data['destination_latitude'] < -90 || $data['destination_latitude'] > 90) {
            throw new Exception("Invalid latitude (must be between -90 and 90)", 400);
        }
        if (!is_numeric($data['destination_longitude']) || $data['destination_longitude'] < -180 || $data['destination_longitude'] > 180) {
            throw new Exception("Invalid longitude (must be between -180 and 180)", 400);
        }

        if (!is_array($data['products']) || empty($data['products'])) {
            throw new Exception("Products must be a non-empty array", 400);
        }
        if (count($data['products']) > 7) {
            throw new Exception("Maximum 7 products per order", 400);
        }
        foreach ($data['products'] as $product) {
            if (!isset($product['product_id']) || !isset($product['quantity'])) {
                throw new Exception("Each product must have product_id and quantity", 400);
            }
            if (!is_numeric($product['product_id']) || $product['product_id'] <= 0) {
                throw new Exception("Invalid product_id", 400);
            }
            if (!is_numeric($product['quantity']) || $product['quantity'] <= 0) {
                throw new Exception("Quantity must be a positive number", 400);
            }
        }

        return $data;
    }

    private function createOrder($data): array
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();


        error_log("Customer ID before order insertion: " . ($data['customer_id'] ?? 'NULL'));

        foreach ($data['products'] as $product) {
            $stmt = $conn->prepare("SELECT is_available FROM products WHERE id = ?");
            if (!$stmt) {
                error_log("Prepare failed for product ID {$product['product_id']}: " . $conn->error);
                throw new Exception("Database error: Unable to verify product availability - " . $conn->error, 500);
            }
            $stmt->bind_param("i", $product['product_id']);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows === 0) {
                throw new Exception("Product ID {$product['product_id']} not found", 404);
            }
            $productData = $result->fetch_assoc();
            if (!$productData['is_available']) {
                throw new Exception("Product ID {$product['product_id']} is not available", 400);
            }
        }

        $tracking_num = $this->generateTrackingNum($conn);
        $conn->begin_transaction();
        try {
            $state = 'Storage';
            $stmt = $conn->prepare(
                "INSERT INTO orders (customer_id, tracking_num, destination_latitude, destination_longitude, state) VALUES (?, ?, ?, ?, ?)"
            );
            if (!$stmt) {
                error_log("Prepare failed for order insertion: " . $conn->error);
                throw new Exception("Database error: Failed to create order - " . $conn->error, 500);
            }

            if (!isset($data['customer_id']) || !is_numeric($data['customer_id'])) {
                throw new Exception("Customer ID is missing or invalid", 500);
            }
            $stmt->bind_param(
                "isdds",
                $data['customer_id'],
                $tracking_num,
                $data['destination_latitude'],
                $data['destination_longitude'],
                $state
            );
            if (!$stmt->execute()) {
                error_log("Order insertion failed: " . $stmt->error);
                throw new Exception("Failed to create order: " . $stmt->error, 500);
            }
            $order_id = $conn->insert_id;

            $stmt = $conn->prepare("INSERT INTO orders_products (order_id, product_id, quantity) VALUES (?, ?, ?)");
            if (!$stmt) {
                error_log("Prepare failed for orders_products insertion: " . $conn->error);
                throw new Exception("Database error: Failed to add products to order - " . $conn->error, 500);
            }
            foreach ($data['products'] as $product) {
                $stmt->bind_param("iii", $order_id, $product['product_id'], $product['quantity']);
                if (!$stmt->execute()) {
                    error_log("Orders_products insertion failed: " . $stmt->error);
                    throw new Exception("Failed to add product to order: " . $stmt->error, 500);
                }
            }

            $conn->commit();
            return [
                'status' => 'success',
                'timestamp' => round(microtime(true) * 1000),
                'data' => [
                    'order_id' => $order_id,
                    'tracking_num' => $tracking_num
                ]
            ];
        } catch (Exception $e) {
            $conn->rollback();
            error_log("CreateOrder failed: " . $e->getMessage());
            throw $e;
        }
    }

    private function generateTrackingNum($conn)
    {
        do {
            $num = 'AA-' . str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
            $stmt = $conn->prepare("SELECT tracking_num FROM orders WHERE tracking_num = ?");
            if (!$stmt) {
                error_log("Prepare failed for tracking number check: " . $conn->error);
                throw new Exception("Database error: Failed to generate tracking number - " . $conn->error, 500);
            }
            $stmt->bind_param("s", $num);
            $stmt->execute();
            $result = $stmt->get_result();
        } while ($result->num_rows > 0);
        return $num;
    }
}

class UpdateOrder
{
    public function __construct() {}

    public function process($data)
    {
        $this->validate($data);
        return $this->updateOrder($data);
    }

    private function validate($data)
    {
        $required = ['apikey', 'type', 'order_id'];
        foreach ($required as $field) {
            if (!isset($data[$field]) || empty($data[$field])) {
                throw new Exception("Field '$field' is required", 400);
            }
        }

        $db = Database::getInstance();
        $conn = $db->getConnection();
        $stmt = $conn->prepare("SELECT id, user_type FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $data['apikey']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("Invalid API key", 401);
        }
        $user = $result->fetch_assoc();
        if ($user['user_type'] !== 'Courier') {
            throw new Exception("Only Couriers can update orders", 403);
        }

        if (!is_numeric($data['order_id']) || $data['order_id'] <= 0) {
            throw new Exception("Invalid order_id", 400);
        }
        if (isset($data['destination_latitude']) && (!is_numeric($data['destination_latitude']) || $data['destination_latitude'] < -90 || $data['destination_latitude'] > 90)) {
            throw new Exception("Invalid latitude (must be between -90 and 90)", 400);
        }
        if (isset($data['destination_longitude']) && (!is_numeric($data['destination_longitude']) || $data['destination_longitude'] < -180 || $data['destination_longitude'] > 180)) {
            throw new Exception("Invalid longitude (must be between -180 and 180)", 400);
        }
        if (isset($data['state']) && !in_array($data['state'], ['Storage', 'Out for delivery', 'Delivered'])) {
            throw new Exception("Invalid state (must be Storage, Out for delivery, or Delivered)", 400);
        }
    }

    private function updateOrder($data): array
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();

        $stmt = $conn->prepare("SELECT order_id FROM orders WHERE order_id = ?");
        $stmt->bind_param("i", $data['order_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("Order not found", 404);
        }

        $fields = [];
        $params = [];
        $types = "";
        if (isset($data['destination_latitude'])) {
            $fields[] = "destination_latitude = ?";
            $params[] = $data['destination_latitude'];
            $types .= "d";
        }
        if (isset($data['destination_longitude'])) {
            $fields[] = "destination_longitude = ?";
            $params[] = $data['destination_longitude'];
            $types .= "d";
        }
        if (isset($data['state'])) {
            $fields[] = "state = ?";
            $params[] = $data['state'];
            $types .= "s";
        }
        if (isset($data['state']) && $data['state'] === 'Delivered') {
            $fields[] = "delivery_date = NOW()";
        }

        if (empty($fields)) {
            throw new Exception("No fields to update", 400);
        }

        $query = "UPDATE orders SET " . implode(", ", $fields) . " WHERE order_id = ?";
        $params[] = $data['order_id'];
        $types .= "i";

        $stmt = $conn->prepare($query);
        if (!$stmt) {
            throw new Exception("Database error: " . $conn->error, 500);
        }
        $stmt->bind_param($types, ...$params);
        if (!$stmt->execute()) {
            throw new Exception("Failed to update order: " . $stmt->error, 500);
        }

        $stmt = $conn->prepare("SELECT order_id, tracking_num, destination_latitude, destination_longitude, state, delivery_date FROM orders WHERE order_id = ?");
        $stmt->bind_param("i", $data['order_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        $order = $result->fetch_assoc();

        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => $order
        ];
    }
}

class GetAllOrders
{
    public function process($data)
    {
        $data = $this->validate($data); 
        return $this->getOrders($data);
    }

    private function validate($data)
    {
        $required = ['apikey', 'type'];
        foreach ($required as $field) {
            if (!isset($data[$field]) || empty($data[$field])) {
                throw new Exception("Field '$field' is required", 400);
            }
        }

        $db = Database::getInstance();
        $conn = $db->getConnection();
        $stmt = $conn->prepare("SELECT id, user_type FROM users WHERE api_key = ?");
        if (!$stmt) {
            error_log("Prepare failed for API key validation: " . $conn->error);
            throw new Exception("Database error: Failed to validate API key", 500);
        }
        $stmt->bind_param("s", $data['apikey']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("Invalid API key", 401);
        }
        $user = $result->fetch_assoc();
        $data['user_id'] = $user['id'];
        $data['user_type'] = $user['user_type'];

        if (!in_array($data['user_type'], ['Customer', 'Courier'])) {
            throw new Exception("Only Customers and Couriers can view orders", 403);
        }

        return $data;
    }

    private function getOrders($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();

        if ($data['user_type'] === 'Courier') {
            $stmt = $conn->prepare(
                "SELECT order_id, tracking_num, destination_latitude, destination_longitude, state, delivery_date 
                 FROM orders 
                 WHERE state = 'Storage'"
            );
            if (!$stmt) {
                error_log("Prepare failed for Courier orders query: " . $conn->error);
                throw new Exception("Database error: Failed to retrieve orders - " . $conn->error, 500);
            }
        } else if ($data['user_type'] === 'Customer') {
            $stmt = $conn->prepare(
                "SELECT order_id, tracking_num, destination_latitude, destination_longitude, state, delivery_date 
                 FROM orders 
                 WHERE customer_id = ? AND state = 'Storage'"
            );
            if (!$stmt) {
                error_log("Prepare failed for Customer orders query: " . $conn->error);
                throw new Exception("Database error: Failed to retrieve orders - " . $conn->error, 500);
            }
            $stmt->bind_param("i", $data['user_id']);
        } else {
            throw new Exception("Only Customers and Couriers can view orders", 403);
        }

        $stmt->execute();
        $result = $stmt->get_result();
        $orders = $result->fetch_all(MYSQLI_ASSOC);

        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => $orders
        ];
    }
}




(new HandleRequest())->handleRequest();
