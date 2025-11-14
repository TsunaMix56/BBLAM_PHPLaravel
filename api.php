<?php
/**
 * BBLAM JWT Authentication API - MySQL Database Version
 * This version connects to MySQL database and uses T_User table for authentication
 */

// Enable error reporting for development
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Include security classes
require_once 'SecurityValidator.php';
require_once 'SSRFGuard.php';

// Set JSON response headers with security
header('Content-Type: application/json');

// CORS headers - เปิดให้ localhost:5173 และทุก origin เรียกได้
if (isset($_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
} else {
    header('Access-Control-Allow-Origin: *');
}
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Accept, Origin');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Max-Age: 86400');

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

// Handle OPTIONS preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit(0);
}

// Database Configuration
class DatabaseConfig {
    private static $instance = null;
    private $connection;

    private function __construct() {
        $host = $_SERVER['DB_HOST'] ?? 'localhost';
        $port = $_SERVER['DB_PORT'] ?? '3306';
        $database = $_SERVER['DB_DATABASE'] ?? 'bblamtestdb';
        $username = $_SERVER['DB_USERNAME'] ?? 'root';
        $password = $_SERVER['DB_PASSWORD'] ?? 'Sql@154465';

        try {
            $this->connection = new PDO(
                "mysql:host={$host};port={$port};dbname={$database};charset=utf8mb4",
                $username,
                $password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]
            );
        } catch (PDOException $e) {
            throw new Exception("Database connection failed: " . $e->getMessage());
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getConnection() {
        return $this->connection;
    }
}

// Simple JWT implementation with configurable secret
class SimpleJWT {
    private static function getSecret() {
        // Use the same secret from Laravel config
        return 'YmQyM2M3ODgtYjg1ZS00Y2IyLWEwZTYtNmIwODcxMTBmYzZmNWQ0OTFlOTUtMmIwZC00MmMwLTg1YWItYjYwODVlYjVlZGI2';
    }
    
    public static function encode($payload) {
        $secret = self::getSecret();
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $payload = json_encode($payload);
        
        $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        
        $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $secret, true);
        $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
        
        return $base64Header . "." . $base64Payload . "." . $base64Signature;
    }
    
    public static function decode($jwt) {
        $secret = self::getSecret();
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return false;
        }
        
        // Verify signature
        $base64Header = $parts[0];
        $base64Payload = $parts[1];
        $signature = $parts[2];
        
        $expectedSignature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $secret, true);
        $expectedBase64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($expectedSignature));
        
        if ($signature !== $expectedBase64Signature) {
            return false;
        }
        
        $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $parts[1])), true);
        
        if ($payload && isset($payload['exp']) && $payload['exp'] > time()) {
            return $payload;
        }
        
        return false;
    }
}

// Simple file-based rate limiting function
function checkRateLimit($identifier, $maxAttempts = 5, $timeWindow = 900) {
    $rateLimitDir = sys_get_temp_dir() . '/rate_limits';
    if (!is_dir($rateLimitDir)) {
        mkdir($rateLimitDir, 0777, true);
    }
    
    $key = md5($identifier);
    $file = $rateLimitDir . '/' . $key . '.json';
    
    // Clean up old file if expired
    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
        if ($data && $data['expires'] < time()) {
            unlink($file);
            $data = null;
        }
    } else {
        $data = null;
    }
    
    // Get current attempts
    $attempts = $data ? $data['attempts'] : 0;
    
    if ($attempts >= $maxAttempts) {
        http_response_code(429);
        echo json_encode([
            'error' => 'Too many attempts. Please try again later.',
            'retry_after' => $timeWindow
        ]);
        exit;
    }
    
    // Store updated attempts
    $newData = [
        'attempts' => $attempts + 1,
        'expires' => time() + $timeWindow
    ];
    file_put_contents($file, json_encode($newData));
    
    return true;
}

// JWT Bearer Token verification function
function verifyJWTBearerToken() {
    $authHeader = '';
    
    // Try to get Authorization header from different sources
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
    } elseif (function_exists('getallheaders')) {
        $headers = getallheaders();
        if ($headers) {
            foreach ($headers as $key => $value) {
                if (strtolower(trim($key)) === 'authorization') {
                    $authHeader = trim($value);
                    break;
                }
            }
        }
    }
    
    // Clean the header value to remove any invalid characters
    $authHeader = preg_replace('/[^\x20-\x7E]/', '', $authHeader);
    $authHeader = trim($authHeader);
    
    if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
        return false;
    }
    
    // Extract JWT token
    $token = trim(substr($authHeader, 7)); // Remove 'Bearer ' prefix
    
    // Verify token
    $payload = SimpleJWT::decode($token);
    return $payload;
}

// User Authentication Class
class UserAuth {
    public $db; // Make public for CreateAccount access

    public function __construct() {
        $this->db = DatabaseConfig::getInstance()->getConnection();
    }

    /**
     * Authenticate user with username and password
     * @param string $username
     * @param string $password
     * @return array|false User data or false if authentication fails
     */
    public function authenticate($username, $password) {
        // Check hardcoded BBLAMTEST1 user first
        if ($username === 'BBLAMTEST1' && $password === '1234Bbl@m') {
            return [
                'id' => 999,
                'username' => 'BBLAMTEST1',
                'name' => 'BBLAM Test User',
                'email' => 'bblamtest1@bblam.co.th',
                'role' => 'admin',
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ];
        }

        // Check database users
        try {
            $stmt = $this->db->prepare("SELECT * FROM T_User WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if (!$user) {
                return false;
            }

            // Support both legacy SHA256+salt and modern Argon2ID
            $isValid = false;
            
            // Check if it's Argon2ID hash (starts with $argon2id$)
            if (strpos($user['password_hash'], '$argon2id$') === 0) {
                $isValid = password_verify($password, $user['password_hash']);
            } elseif (strpos($user['password_hash'], '$2y$') === 0) {
                // bcrypt fallback
                $isValid = password_verify($password, $user['password_hash']);
            } else {
                // Legacy SHA256 + salt verification
                $hashedPassword = hash('sha256', $password . $user['salt']);
                $isValid = hash_equals($user['password_hash'], $hashedPassword);
            }
            
            if ($isValid) {
                return [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'name' => $user['username'], 
                    'email' => $user['username'] . '@bblam.co.th',
                    'role' => $user['role'] ?? 'user',
                    'created_at' => $user['created_at'],
                    'updated_at' => $user['updated_at']
                ];
            }

            return false;
        } catch (Exception $e) {
            error_log("Authentication error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Get user by ID
     * @param int $id
     * @return array|false
     */
    public function getUserById($id) {
        // Check hardcoded BBLAMTEST1 user first
        if ($id == 999) {
            return [
                'id' => 999,
                'username' => 'BBLAMTEST1',
                'name' => 'BBLAM Test User',
                'email' => 'bblamtest1@bblam.co.th',
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ];
        }

        // Check database users
        try {
            $stmt = $this->db->prepare("SELECT * FROM T_User WHERE id = ?");
            $stmt->execute([$id]);
            $user = $stmt->fetch();

            if ($user) {
                return [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'name' => $user['username'],
                    'email' => $user['username'] . '@bblam.co.th',
                    'created_at' => $user['created_at'],
                    'updated_at' => $user['updated_at']
                ];
            }

            return false;
        } catch (Exception $e) {
            error_log("Get user error: " . $e->getMessage());
            return false;
        }
    }
}

// Router - parse the request path
$request_uri = $_SERVER['REQUEST_URI'];
$path = parse_url($request_uri, PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

// Remove base path if necessary
$path = str_replace('/index.php', '', $path);

// Route handling
switch ($path) {
    case '/':
        // API root - show available endpoints
        echo json_encode([
            'success' => true,
            'message' => 'BBLAM JWT Authentication API',
            'version' => '1.0.0',
            'server_time' => date('c'),
            'endpoints' => [
                'POST /api/auth/token' => 'Get JWT token using Basic Auth',
                'POST /api/auth/create-account' => 'Create account (requires JWT Bearer)',
                'POST /api/auth/login' => 'Login (requires JWT Bearer)',
                'GET /api/auth/profile' => 'Get user profile (requires JWT)',
                'POST /api/auth/refresh' => 'Refresh JWT token',
                'POST /api/auth/logout' => 'Logout and invalidate token',
                'POST /api/safe-request' => 'SSRF-protected HTTP request (requires JWT)'
            ],
            'test_credentials' => [
                'fixed_user' => 'BBLAMTEST1:1234Bbl@m (hardcoded)',
                'database_users' => 'test2345:1234, admin:admin123',
                'note' => 'Use BBLAMTEST1 credentials for testing'
            ],
            'database' => [
                'status' => 'Connected to MySQL bblamtestdb',
                'table' => 'T_User'
            ],
            'note' => 'API is running successfully!'
        ]);
        break;
        
    case '/api/auth/token':
        if ($method !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST.']);
            break;
        }
        
        // Apply rate limiting for token requests
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        checkRateLimit('GetToken_' . $clientIp, 10, 30); // 10 attempts per 30 seconds
        
        // Get Authorization header with cleaning
        $authHeader = '';
        
        // Try to get Authorization header from different sources
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (function_exists('getallheaders')) {
            $headers = getallheaders();
            if ($headers) {
                foreach ($headers as $key => $value) {
                    if (strtolower(trim($key)) === 'authorization') {
                        $authHeader = trim($value);
                        break;
                    }
                }
            }
        }
        
        // Clean the header value to remove any invalid characters
        $authHeader = preg_replace('/[^\x20-\x7E]/', '', $authHeader);
        $authHeader = trim($authHeader);
        
        if (!$authHeader || !str_starts_with($authHeader, 'Basic ')) {
            http_response_code(401);
            echo json_encode([
                'error' => 'Missing or invalid Authorization header. Expected Basic authentication.',
                'example' => 'Authorization: Basic QkJMQU1URVNUMToxMjM0QmJsQG0='
            ]);
            break;
        }
        
        // Decode Basic Auth
        $encodedCredentials = substr($authHeader, 6);
        $decodedCredentials = base64_decode($encodedCredentials);
        
        if (!$decodedCredentials || !str_contains($decodedCredentials, ':')) {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid Basic authentication format.']);
            break;
        }
        
        [$username, $password] = explode(':', $decodedCredentials, 2);
        
        // Authenticate user with database
        $userAuth = new UserAuth();
        $user = $userAuth->authenticate($username, $password);
        
        if (!$user) {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid credentials.']);
            break;
        }
        
        // Generate JWT
        $payload = [
            'sub' => $user['id'],
            'username' => $user['username'],
            'name' => $user['name'],
            'email' => $user['email'],
            'role' => $user['role'] ?? 'user',
            'iat' => time(),
            'exp' => time() + 3600, // 1 hour expiration
            'iss' => 'BBLAM-API',
            'aud' => 'BBLAM-CLIENT'
        ];

        $token = SimpleJWT::encode($payload);

        echo json_encode([
            'success' => true,
            'message' => 'JWT token generated successfully',
            'data' => [
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => date('c', time() + 3600), // Return as ISO 8601 datetime
                'user' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'name' => $user['name'],
                    'email' => $user['email']
                ]
            ]
        ]);
        break;
        
    case '/api/auth/profile':
        if ($method !== 'GET') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use GET.']);
            break;
        }
        
        // Get authorization header
        $headers = getallheaders() ?: [];
        $authHeader = '';
        
        foreach ($headers as $key => $value) {
            if (strtolower($key) === 'authorization') {
                $authHeader = $value;
                break;
            }
        }
        
        if (!$authHeader && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
        }
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            http_response_code(401);
            echo json_encode([
                'error' => 'Missing or invalid Authorization header. Expected Bearer token.',
                'example' => 'Authorization: Bearer YOUR_JWT_TOKEN'
            ]);
            break;
        }
        
        $token = substr($authHeader, 7);
        $payload = SimpleJWT::decode($token);
        
        if (!$payload) {
            http_response_code(401);
            echo json_encode(['error' => 'Token is invalid or expired']);
            break;
        }

        // Get user data from database
        $userAuth = new UserAuth();
        $user = $userAuth->getUserById($payload['sub']);

        if (!$user) {
            http_response_code(401);
            echo json_encode(['error' => 'User not found']);
            break;
        }

        echo json_encode([
            'success' => true,
            'data' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'name' => $user['name'],
                'email' => $user['email'],
                'created_at' => $user['created_at'],
                'updated_at' => $user['updated_at'],
                'token_issued_at' => date('c', $payload['iat']),
                'token_expires_at' => date('c', $payload['exp'])
            ]
        ]);
        break;
        
    case '/api/auth/refresh':
        if ($method !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST.']);
            break;
        }
        
        // Get authorization header
        $headers = getallheaders() ?: [];
        $authHeader = '';
        
        foreach ($headers as $key => $value) {
            if (strtolower($key) === 'authorization') {
                $authHeader = $value;
                break;
            }
        }
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            http_response_code(401);
            echo json_encode(['error' => 'Missing or invalid Authorization header. Expected Bearer token.']);
            break;
        }
        
        $token = substr($authHeader, 7);
        $payload = SimpleJWT::decode($token);
        
        if (!$payload) {
            http_response_code(401);
            echo json_encode(['error' => 'Token is invalid']);
            break;
        }
        
        // Generate new token with fresh expiration
        $newPayload = [
            'sub' => $payload['sub'],
            'username' => $payload['username'],
            'name' => $payload['name'],
            'email' => $payload['email'],
            'iat' => time(),
            'exp' => time() + 3600, // 1 hour expiration
            'iss' => 'BBLAM-API',
            'aud' => 'BBLAM-CLIENT'
        ];
        
        $newToken = SimpleJWT::encode($newPayload);
        
        echo json_encode([
            'success' => true,
            'message' => 'Token refreshed successfully',
            'data' => [
                'access_token' => $newToken,
                'token_type' => 'bearer',
                'expires_in' => date('c', time() + 3600) // Return as ISO 8601 datetime
            ]
        ]);
        break;
        
    case '/api/auth/logout':
        if ($method !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST.']);
            break;
        }
        
        // In a real implementation, you would invalidate the token in a blacklist
        echo json_encode([
            'success' => true,
            'message' => 'Successfully logged out'
        ]);
        break;
        
    case '/api/auth/create-account':
        if ($method !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST.']);
            break;
        }
        
        // Apply rate limiting for account creation
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        checkRateLimit('CreateAccount_' . $clientIp, 3, 30); // 3 accounts per 30 seconds
        
        // Verify JWT Bearer Token
        $jwtPayload = verifyJWTBearerToken();
        if (!$jwtPayload) {
            http_response_code(401);
            echo json_encode([
                'success' => false,
                'error' => 'Invalid or expired JWT Bearer token required'
            ]);
            break;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        // Strong validation
        if (!isset($input['username']) || !isset($input['password'])) {
            http_response_code(422);
            echo json_encode([
                'success' => false,
                'error' => 'Username and password are required'
            ]);
            break;
        }
        
        // Username validation
        if (strlen($input['username']) < 3 || strlen($input['username']) > 30) {
            http_response_code(422);
            echo json_encode([
                'success' => false,
                'error' => 'Username must be between 3 and 30 characters'
            ]);
            break;
        }
        
        if (!preg_match('/^[a-zA-Z][a-zA-Z0-9_]*$/', $input['username'])) {
            http_response_code(422);
            echo json_encode([
                'success' => false,
                'error' => 'Username must start with letter and contain only letters, numbers, and underscores'
            ]);
            break;
        }
        
        // Check reserved usernames
        $reserved = ['admin', 'root', 'system', 'api', 'test', 'guest', 'anonymous', 'null', 'undefined'];
        if (in_array(strtolower($input['username']), $reserved)) {
            http_response_code(422);
            echo json_encode([
                'success' => false,
                'error' => 'Username is reserved and cannot be used'
            ]);
            break;
        }
        
        if (strlen($input['password']) < 6) {
            http_response_code(422);
            echo json_encode([
                'success' => false,
                'error' => 'Password must be at least 6 characters'
            ]);
            break;
        }
        
        // Save to T_User database using MySQL
        try {
            $userAuth = new UserAuth();
            
            // Strong password validation
            if (strlen($input['password']) < 12) {
                http_response_code(422);
                echo json_encode([
                    'success' => false,
                    'error' => 'Password must be at least 12 characters long'
                ]);
                break;
            }
            
            if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/', $input['password'])) {
                http_response_code(422);
                echo json_encode([
                    'success' => false,
                    'error' => 'Password must contain uppercase, lowercase, number, and special character'
                ]);
                break;
            }
            
            // Use Argon2ID for secure password hashing
            $passwordHash = password_hash($input['password'], PASSWORD_ARGON2ID, [
                'memory_cost' => 65536, // 64 MB
                'time_cost' => 4,       // 4 iterations
                'threads' => 3          // 3 threads
            ]);
            
            // Generate salt for compatibility (though not needed for Argon2ID)
            $salt = bin2hex(random_bytes(16));
            $createdBy = $input['created_by'] ?? 'API';
            
            // Check if user exists
            $stmt = $userAuth->db->prepare("SELECT COUNT(*) as count FROM T_User WHERE username = ?");
            $stmt->execute([$input['username']]);
            $userExists = $stmt->fetch()['count'] > 0;
            
            if ($userExists) {
                http_response_code(409);
                echo json_encode([
                    'success' => false,
                    'error' => 'Username already exists in database'
                ]);
                break;
            }
            
            // Insert new user with role
            $role = $input['role'] ?? 'user'; // Default to 'user' role
            
            // Only admins can create admin accounts
            if ($role === 'admin') {
                $currentUser = $jwtPayload['role'] ?? 'user';
                if ($currentUser !== 'admin') {
                    http_response_code(403);
                    echo json_encode([
                        'success' => false,
                        'error' => 'Only administrators can create admin accounts'
                    ]);
                    break;
                }
            }
            
            $stmt = $userAuth->db->prepare("
                INSERT INTO T_User (username, password_hash, salt, role, created_at, updated_at) 
                VALUES (?, ?, ?, ?, NOW(), NOW())
            ");
            $stmt->execute([$input['username'], $passwordHash, $salt, $role]);
            
            $userId = $userAuth->db->lastInsertId();
            
            // Get created user info
            $stmt = $userAuth->db->prepare("SELECT * FROM T_User WHERE id = ?");
            $stmt->execute([$userId]);
            $newUser = $stmt->fetch();
            
            echo json_encode([
                'success' => true,
                'message' => 'Account created successfully in MySQL T_User database',
                'data' => [
                    'id' => (int)$newUser['id'],
                    'username' => $newUser['username'],
                    'created_at' => $newUser['created_at'],
                    'updated_at' => $newUser['updated_at']
                ]
            ]);
            
        } catch (Exception $e) {
            error_log("MySQL create account error: " . $e->getMessage());
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => 'Database error: ' . $e->getMessage()
            ]);
        }
        break;
        
    case '/api/auth/login':
        if ($method !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST.']);
            break;
        }
        
        // Apply rate limiting for login attempts
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        checkRateLimit('Login_' . $clientIp, 5, 30); // 5 attempts per 30 seconds
        
        // Verify JWT Bearer Token
        $jwtPayload = verifyJWTBearerToken();
        if (!$jwtPayload) {
            http_response_code(401);
            echo json_encode([
                'success' => false,
                'error' => 'Invalid or expired JWT Bearer token required'
            ]);
            break;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        // Validation
        if (!isset($input['username']) || !isset($input['password'])) {
            http_response_code(422);
            echo json_encode([
                'success' => false,
                'error' => 'Username and password are required'
            ]);
            break;
        }
        
        // Connect to MySQL database to verify user credentials
        try {
            $userAuth = new UserAuth();
            
            // Use same authenticate method as /api/auth/token
            $user = $userAuth->authenticate($input['username'], $input['password']);
            
            if (!$user) {
                http_response_code(401);
                echo json_encode([
                    'success' => false,
                    'error' => 'Invalid username or password'
                ]);
                break;
            }
            
            // Use actual user data for response
            $userForResponse = [
                'id' => $user['id'],
                'username' => $user['username']
            ];
            
        } catch (Exception $e) {
            error_log("MySQL login error: " . $e->getMessage());
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => 'Database error: ' . $e->getMessage()
            ]);
            break;
        }
        
        // Generate JWT token
        $payload = [
            'sub' => $userForResponse['id'],
            'username' => $userForResponse['username'],
            'iat' => time(),
            'exp' => time() + (60 * 60), // 1 hour expiration
            'iss' => 'BBLAM-API',
            'aud' => 'BBLAM-CLIENT'
        ];
        
        $token = SimpleJWT::encode($payload);
        
        if (!$token) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => 'Could not create token'
            ]);
            break;
        }
        
        echo json_encode([
            'success' => true,
            'Message' => "Welcome ".$userForResponse['username'],
            'role' => $user['role'] ?? 'user'
        ]);
        break;
        
    case '/test':
        // Test endpoint to verify the API is working
        echo json_encode([
            'success' => true,
            'message' => 'API is working!',
            'php_version' => phpversion(),
            'server_time' => date('c'),
            'request_method' => $method,
            'request_path' => $path
        ]);
        break;
        
    default:
        http_response_code(404);
        echo json_encode([
            'error' => 'Endpoint not found',
            'available_endpoints' => [
                '/' => 'API information',
                '/api/auth/token' => 'Get JWT token (Basic Auth)',
                '/api/auth/create-account' => 'Create new account (requires JWT Bearer)',
                '/api/auth/login' => 'Login with username/password (requires JWT Bearer)',
                '/api/auth/profile' => 'Get user profile (requires JWT Bearer)',
                '/api/auth/refresh' => 'Refresh token (requires JWT Bearer)',
                '/api/auth/logout' => 'Logout (requires JWT Bearer)',
                '/test' => 'Test endpoint'
            ]
        ]);
        break;
        
    case '/api/safe-request':
        if ($method !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST.']);
            break;
        }
        
        // Verify JWT Bearer Token
        $jwtPayload = verifyJWTBearerToken();
        if (!$jwtPayload) {
            break; // Error already sent by verifyJWTBearerToken
        }
        
        // Get request data
        $rawInput = file_get_contents('php://input');
        $input = json_decode($rawInput, true);
        
        if (!isset($input['url'])) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => 'URL parameter required'
            ]);
            break;
        }
        
        try {
            // Use SSRF Guard to make safe HTTP request
            $result = SSRFGuard::safeHttpRequest($input['url'], [
                CURLOPT_HTTPHEADER => $input['headers'] ?? [],
                CURLOPT_POSTFIELDS => $input['data'] ?? null,
            ]);
            
            echo json_encode([
                'success' => true,
                'url' => $input['url'],
                'http_code' => $result['http_code'],
                'body' => $result['body'],
                'message' => 'Request completed successfully'
            ]);
            
        } catch (Exception $e) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
        break;
}
?>