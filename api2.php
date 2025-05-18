<?php
/*
Amantle Keamogetse Temo u23539764
Aundrea Ncube u22747363
*/

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Origin: http://localhost:4200');
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
            case 'CreateDrone' :
                $handler = new CreateDrone();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'UpdateDrone':
                $handler = new UpdateDrone();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'GetAllDrones':
                $handler = new GetAllDrones();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'GetUserById':
                $handler = new GetUserById();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'CurrentlyDelivering':
                $handler = new CurrentlyDelivering();
                $response = $handler->process($input);
                $this->sendResponse(200, $response);
                break;
            case 'GetDeliveryRequests':
                $handler = new GetDeliveryRequests();
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
    private const valid_usertypes = ['Customer', 'Courier', 'Distributor', 'Distributor'];

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
        $stmt = $conn->prepare("SELECT name, surname , user_type FROM users WHERE api_key = ?");
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
                'surname' => $user['surname'],
                'user_type'=>$user['user_type']
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
            $num = 'CS-' . str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
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
            $stmt = $conn->prepare("
                SELECT o.order_id, o.tracking_num, o.destination_latitude, o.destination_longitude, o.state, o.delivery_date, o.customer_id,
                       op.product_id, op.quantity, p.title
                FROM orders o
                LEFT JOIN orders_products op ON o.order_id = op.order_id
                LEFT JOIN products p ON op.product_id = p.id
                WHERE o.state = 'Storage'
            ");
        } else if ($data['user_type'] === 'Customer') {
            $stmt = $conn->prepare("
                SELECT o.order_id, o.tracking_num, o.destination_latitude, o.destination_longitude, o.state, o.delivery_date, o.customer_id,
                       op.product_id, op.quantity, p.title
                FROM orders o
                LEFT JOIN orders_products op ON o.order_id = op.order_id
                LEFT JOIN products p ON op.product_id = p.id
                WHERE o.customer_id = ? AND o.state = 'Storage'
            ");
            $stmt->bind_param("i", $data['user_id']);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        $orders = [];
        $current_order = null;
        while ($row = $result->fetch_assoc()) {
            if (!$current_order || $current_order['order_id'] !== $row['order_id']) {
                if ($current_order) {
                    $orders[] = $current_order;
                }
                $current_order = [
                    'order_id' => $row['order_id'],
                    'tracking_num' => $row['tracking_num'],
                    'destination_latitude' => $row['destination_latitude'],
                    'destination_longitude' => $row['destination_longitude'],
                    'state' => $row['state'],
                    'delivery_date' => $row['delivery_date'],
                    'customer_id' => $row['customer_id'],
                    'products' => []
                ];
            }
            if ($row['product_id']) {
                $current_order['products'][] = [
                    'product_id' => $row['product_id'],
                    'quantity' => $row['quantity'],
                    'title' => $row['title']
                ];
            }
        }
        if ($current_order) {
            $orders[] = $current_order;
        }
        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => $orders
        ];
    }
}



class GetDeliveryRequests
{
    public function process($data)
    {
        $data = $this->validate($data);
        return $this->getRequests($data);
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
        $stmt = $conn->prepare("SELECT id, user_type, email FROM users WHERE api_key = ?");
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
        if (!in_array($user['user_type'], ['Courier', 'Distributor'])) {
            throw new Exception("Only Couriers and Distributors can view delivery requests", 403);
        }
        $data['user_id'] = $user['id'];
        $data['user_type'] = $user['user_type'];
        $data['email'] = $user['email'];

        return $data;
    }

    private function getRequests($data)
    {
        // Note: Since deliveryRequests is managed in server.js, this endpoint simulates fetching from a database.
        // In a real system, you'd store requests in a database table.
        // For now, return an empty array as server.js handles the actual requests via WebSocket.
        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => []
        ];
    }
}




class CreateDrone
{
    public function __construct() {}

    public function process($data)
    {
        $data = $this->validate($data);
        return $this->createDrone($data);
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
        if (!in_array($user['user_type'], ['Courier', 'Distributor'])) {
            throw new Exception("Only Couriers or Distributors can create drones", 403);
        }
        $data['user_id'] = $user['id'];

    
        if (isset($data['latest_latitude']) && (!is_numeric($data['latest_latitude']) || $data['latest_latitude'] < -90 || $data['latest_latitude'] > 90)) {
            throw new Exception("Invalid latitude (must be between -90 and 90)", 400);
        }
        if (isset($data['latest_longitude']) && (!is_numeric($data['latest_longitude']) || $data['latest_longitude'] < -180 || $data['latest_longitude'] > 180)) {
            throw new Exception("Invalid longitude (must be between -180 and 180)", 400);
        }
        if (isset($data['altitude']) && (!is_numeric($data['altitude']) || $data['altitude'] < 0)) {
            throw new Exception("Invalid altitude (must be non-negative)", 400);
        }
        if (isset($data['battery_level']) && (!is_numeric($data['battery_level']) || $data['battery_level'] < 0 || $data['battery_level'] > 100)) {
            throw new Exception("Invalid battery level (must be between 0 and 100)", 400);
        }

        return $data;
    }

    private function createDrone($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();

        $latestLatitude = isset($data['latest_latitude']) ? $data['latest_latitude'] : -25.7545;
        $latestLongitude = isset($data['latest_longitude']) ? $data['latest_longitude'] : 28.2314;
        $altitude = isset($data['altitude']) ? $data['altitude'] : 0;
        $batteryLevel = isset($data['battery_level']) ? $data['battery_level'] : 100;
        $isAvailable = 1; 

        $stmt = $conn->prepare("
            INSERT INTO drones 
            (current_operator_id, is_available, latest_latitude, latest_longitude, altitude, battery_level) 
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        if (!$stmt) {
            error_log("Prepare failed for drone insertion: " . $conn->error);
            throw new Exception("Database error: Failed to create drone - " . $conn->error, 500);
        }
        $stmt->bind_param("iiddid", $data['user_id'], $isAvailable, $latestLatitude, $latestLongitude, $altitude, $batteryLevel);
        if (!$stmt->execute()) {
            error_log("Drone insertion failed: " . $stmt->error);
            throw new Exception("Failed to create drone: " . $stmt->error, 500);
        }
        $droneId = $conn->insert_id;

        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => [
                'id' => $droneId,
                'current_operator_id' => $data['user_id'],
                'is_available' => (bool)$isAvailable,
                'latest_latitude' => $latestLatitude,
                'latest_longitude' => $latestLongitude,
                'altitude' => $altitude,
                'battery_level' => $batteryLevel
            ]
        ];
    }
}

class UpdateDrone
{
    public function __construct() {}

    public function process($data)
    {
        $data = $this->validate($data);
        return $this->updateDrone($data);
    }

    private function validate($data)
    {
        $required = ['apikey', 'type', 'id'];
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
        if (!in_array($user['user_type'], ['Courier', 'Distributor'])) {
            throw new Exception("Only Couriers or Distributors can update drones", 403);
        }
        $data['user_id'] = $user['id'];

        if (!is_numeric($data['id']) || $data['id'] <= 0) {
            throw new Exception("Invalid drone ID", 400);
        }
        $stmt = $conn->prepare("SELECT current_operator_id FROM drones WHERE id = ?");
        if (!$stmt) {
            error_log("Prepare failed for drone ID validation: " . $conn->error);
            throw new Exception("Database error: Failed to validate drone ID", 500);
        }
        $stmt->bind_param("i", $data['id']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("Drone not found", 404);
        }
        $drone = $result->fetch_assoc();
        if ($drone['current_operator_id'] !== $data['user_id']) {
            throw new Exception("You are not the operator of this drone", 403);
        }


        if (isset($data['latest_latitude']) && (!is_numeric($data['latest_latitude']) || $data['latest_latitude'] < -90 || $data['latest_latitude'] > 90)) {
            throw new Exception("Invalid latitude (must be between -90 and 90)", 400);
        }
        if (isset($data['latest_longitude']) && (!is_numeric($data['latest_longitude']) || $data['latest_longitude'] < -180 || $data['latest_longitude'] > 180)) {
            throw new Exception("Invalid longitude (must be between -180 and 180)", 400);
        }
        if (isset($data['altitude']) && (!is_numeric($data['altitude']) || $data['altitude'] < 0)) {
            throw new Exception("Invalid altitude (must be non-negative)", 400);
        }
        if (isset($data['battery_level']) && (!is_numeric($data['battery_level']) || $data['battery_level'] < 0 || $data['battery_level'] > 100)) {
            throw new Exception("Invalid battery level (must be between 0 and 100)", 400);
        }
        if (isset($data['is_available']) && !is_bool($data['is_available'])) {
            throw new Exception("Invalid is_available (must be boolean)", 400);
        }
        if (isset($data['current_operator_id'])) {
            if ($data['current_operator_id'] !== null) {
                $stmt = $conn->prepare("SELECT id FROM users WHERE id = ? AND user_type IN ('Courier', 'Distributor')");
                if (!$stmt) {
                    error_log("Prepare failed for operator ID validation: " . $conn->error);
                    throw new Exception("Database error: Failed to validate operator ID", 500);
                }
                $stmt->bind_param("i", $data['current_operator_id']);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows === 0) {
                    throw new Exception("Invalid current operator ID", 400);
                }
            }
        }

        return $data;
    }

    private function updateDrone($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();

        $fields = [];
        $params = [];
        $types = "";
        if (isset($data['current_operator_id'])) {
            $fields[] = "current_operator_id = ?";
            $params[] = $data['current_operator_id'];
            $types .= "i";
        }
        if (isset($data['is_available'])) {
            $fields[] = "is_available = ?";
            $params[] = $data['is_available'] ? 1 : 0;
            $types .= "i";
        }
        if (isset($data['latest_latitude'])) {
            $fields[] = "latest_latitude = ?";
            $params[] = $data['latest_latitude'];
            $types .= "d";
        }
        if (isset($data['latest_longitude'])) {
            $fields[] = "latest_longitude = ?";
            $params[] = $data['latest_longitude'];
            $types .= "d";
        }
        if (isset($data['altitude'])) {
            $fields[] = "altitude = ?";
            $params[] = $data['altitude'];
            $types .= "d";
        }
        if (isset($data['battery_level'])) {
            $fields[] = "battery_level = ?";
            $params[] = $data['battery_level'];
            $types .= "i";
        }

        if (empty($fields)) {
            throw new Exception("No fields to update", 400);
        }

        $query = "UPDATE drones SET " . implode(", ", $fields) . " WHERE id = ?";
        $params[] = $data['id'];
        $types .= "i";

        $stmt = $conn->prepare($query);
        if (!$stmt) {
            error_log("Prepare failed for drone update: " . $conn->error);
            throw new Exception("Database error: Failed to update drone - " . $conn->error, 500);
        }
        $stmt->bind_param($types, ...$params);
        if (!$stmt->execute()) {
            error_log("Drone update failed: " . $stmt->error);
            throw new Exception("Failed to update drone: " . $stmt->error, 500);
        }

        $stmt = $conn->prepare("SELECT id, current_operator_id, is_available, latest_latitude, latest_longitude, altitude, battery_level FROM drones WHERE id = ?");
        if (!$stmt) {
            error_log("Prepare failed for drone fetch: " . $conn->error);
            throw new Exception("Database error: Failed to fetch drone - " . $conn->error, 500);
        }
        $stmt->bind_param("i", $data['id']);
        $stmt->execute();
        $result = $stmt->get_result();
        $drone = $result->fetch_assoc();
        $drone['is_available'] = (bool)$drone['is_available'];

        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => $drone
        ];
    }
}


class GetAllDrones
{
    public function __construct() {}

    public function process($data)
    {
        $data = $this->validate($data);
        return $this->getDrones($data);
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
        if (!in_array($user['user_type'], ['Courier', 'Distributor'])) {
            throw new Exception("Only Couriers or Distributors can view drones", 403);
        }
        $data['user_id'] = $user['id'];

        return $data;
    }

    private function getDrones($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();

        $stmt = $conn->prepare("
            SELECT d.id, d.current_operator_id, d.is_available, d.latest_latitude, d.latest_longitude, d.altitude, d.battery_level, 
                   u.name AS operator_name, u.surname AS operator_surname 
            FROM drones d 
            LEFT JOIN users u ON d.current_operator_id = u.id
        ");
        if (!$stmt) {
            error_log("Prepare failed for drones query: " . $conn->error);
            throw new Exception("Database error: Failed to retrieve drones - " . $conn->error, 500);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        $drones = $result->fetch_all(MYSQLI_ASSOC);

        foreach ($drones as &$drone) {
            $drone['is_available'] = (bool)$drone['is_available'];
        }

        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => $drones
        ];
    }
}


class GetUserById
{

    public function __construct() {}

    public function process($data)
    {
        $this->validate($data);
        return $this->getUserById($data);
    }

    private function validate($data)
    {
        if (empty($data['apikey'])) {
            throw new Exception("Field 'apikey' is required", 400);
        }
        if (empty($data['user_id']) || !is_numeric($data['user_id']) || $data['user_id'] <= 0) {
            throw new Exception("Field 'user_id' must be a positive integer", 400);
        }
    }

    private function getUserById($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();
        // Validate apikey and user_type
        $stmt = $conn->prepare("SELECT id, user_type FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $data['apikey']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("Invalid API key", 401);
        }
        $auth_user = $result->fetch_assoc();
        if (!in_array($auth_user['user_type'], ['Courier', 'Distributor'])) {
            throw new Exception("Only Couriers and Distributors can access user details", 403);
        }
      
        $stmt = $conn->prepare("SELECT name, surname, user_type FROM users WHERE id = ?");
        $stmt->bind_param("i", $data['user_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("User not found", 404);
        }
        $user = $result->fetch_assoc();
        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => [
                'name' => $user['name'],
                'surname' => $user['surname'],
                'user_type' => $user['user_type']
            ]
        ];
    }
}



class CurrentlyDelivering
{
    public function process($data)
    {
        $data = $this->validate($data);
        return $this->getDeliveringOrders($data);
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
        if (!in_array($user['user_type'], ['Customer', 'Courier', 'Distributor'])) {
            throw new Exception("Only Customers, Couriers, or Distributors can view delivering orders", 403);
        }
        $data['user_id'] = $user['id'];
        $data['user_type'] = $user['user_type'];

        return $data;
    }

    private function getDeliveringOrders($data)
    {
        $db = Database::getInstance();
        $conn = $db->getConnection();
        $query = "
            SELECT o.order_id, o.tracking_num, o.destination_latitude, o.destination_longitude, o.state, o.delivery_date, o.customer_id,
                   op.product_id, op.quantity, p.title, p.image_url,
                   u.name AS customer_name, u.surname AS customer_surname
            FROM orders o
            LEFT JOIN orders_products op ON o.order_id = op.order_id
            LEFT JOIN products p ON op.product_id = p.id
            LEFT JOIN users u ON o.customer_id = u.id
            WHERE o.state = 'Out for delivery'
        ";
        if ($data['user_type'] === 'Customer') {
            $query .= " AND o.customer_id = ?";
        }
        $stmt = $conn->prepare($query);
        if (!$stmt) {
            error_log("Prepare failed for delivering orders query: " . $conn->error);
            throw new Exception("Database error: Failed to retrieve delivering orders - " . $conn->error, 500);
        }
        if ($data['user_type'] === 'Customer') {
            $stmt->bind_param("i", $data['user_id']);
        }
        $stmt->execute();
        $result = $stmt->get_result();
        $orders = [];
        $current_order = null;
        while ($row = $result->fetch_assoc()) {
            if (!$current_order || $current_order['order_id'] !== $row['order_id']) {
                if ($current_order) {
                    $orders[] = $current_order;
                }
                $current_order = [
                    'order_id' => $row['order_id'],
                    'tracking_num' => $row['tracking_num'],
                    'destination' => [$row['destination_latitude'], $row['destination_longitude']],
                    'state' => $row['state'],
                    'delivery_date' => $row['delivery_date'],
                    'customer_id' => $row['customer_id'],
                    'recipient' => [
                        'name' => $row['customer_name'],
                        'surname' => $row['customer_surname']
                    ],
                    'products' => []
                ];
            }
            if ($row['product_id']) {
                $current_order['products'][] = [
                    'product_id' => $row['product_id'],
                    'quantity' => $row['quantity'],
                    'title' => $row['title'],
                    'image_url' => $row['image_url']
                ];
            }
        }
        if ($current_order) {
            $orders[] = $current_order;
        }
        return [
            'status' => 'success',
            'timestamp' => round(microtime(true) * 1000),
            'data' => $orders
        ];
    }
}


(new HandleRequest())->handleRequest();
