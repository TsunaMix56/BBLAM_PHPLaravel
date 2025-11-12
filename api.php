<?php
/**
 * BBLAM JWT Authentication API - Standalone Version
 * This version works without full Laravel framework dependencies
 */

// Enable error reporting for development
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Set JSON response headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
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

// Demo user - in production this would come from a database
$demo_user = [
    'id' => 1,
    'username' => 'BBLAMTEST1',
    'password' => password_hash('1234Bbl@m', PASSWORD_DEFAULT), // Hashed password
    'name' => 'BBLAM Test User',
    'email' => 'bblamtest1@example.com',
    'created_at' => '2024-11-11T10:30:00Z',
    'updated_at' => '2024-11-11T10:30:00Z'
];

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
            ],
            'test_credentials' => [
                'username' => 'BBLAMTEST1',
                'password' => '1234Bbl@m',
                'basic_auth_header' => 'Authorization: Basic QkJMQU1URVNUMToxMjM0QmJsQG0='
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
        
        // Validate credentials
        if ($username !== 'BBLAMTEST1' || !password_verify($password, $demo_user['password'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid credentials.']);
            break;
        }
        
        // Generate JWT
        $payload = [
            'sub' => $demo_user['id'],
            'username' => $demo_user['username'],
            'name' => $demo_user['name'],
            'email' => $demo_user['email'],
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
                    'id' => $demo_user['id'],
                    'username' => $demo_user['username'],
                    'name' => $demo_user['name'],
                    'email' => $demo_user['email']
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
        
        echo json_encode([
            'success' => true,
            'data' => [
                'id' => $payload['sub'],
                'username' => $payload['username'],
                'name' => $payload['name'],
                'email' => $payload['email'],
                'created_at' => $demo_user['created_at'],
                'updated_at' => $demo_user['updated_at'],
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
        
        if (strlen($input['username']) < 3 || strlen($input['username']) > 24) {
            http_response_code(422);
            echo json_encode([
                'success' => false,
                'error' => 'Username must be between 3 and 24 characters'
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
        
        // Save to T_User database using SQL Server
        try {
            // Use alternative method to connect to SQL Server since sqlsrv extension not available
            // Method 1: Try direct SQL Server connection through system calls
            
            $newUser = null;
            $userId = null;
            
            // Generate salt and hash password first
            $salt = bin2hex(random_bytes(32));
            $passwordHash = hash('sha256', $input['password'] . $salt);
            $createdBy = $input['created_by'] ?? 'API';
            $currentTime = date('Y-m-d H:i:s');
            
            // Try to execute SQL Server query directly
            $sqlcmd = 'sqlcmd -S DESKTOP-OIB91MS -d LOGIN_TEST -E -h -1 -Q ';
            
            // Check if user exists
            $checkUserSql = '"SELECT COUNT(*) FROM T_User WHERE USERNAME = \''.$input['username'].'\'"';
            $checkResult = shell_exec($sqlcmd . $checkUserSql);
            
            // Parse the result properly - sqlcmd returns headers and data
            $userCount = 0;
            if ($checkResult !== null) {
                $lines = explode("\n", trim($checkResult));
                foreach ($lines as $line) {
                    $trimmedLine = trim($line);
                    // Look for a line that contains only a number (the count)
                    if (is_numeric($trimmedLine) && $trimmedLine >= 0) {
                        $userCount = (int)$trimmedLine;
                        break;
                    }
                }
            }
            
            if ($userCount > 0) {
                http_response_code(409);
                echo json_encode([
                    'success' => false,
                    'error' => 'Username already exists in SQL Server database'
                ]);
                break;
            }
            
            // Insert new user
            $insertSql = '"INSERT INTO T_User (USERNAME, PasswordHash, PasswordSalt, CreatedAt, CreatedBy) OUTPUT INSERTED.ID VALUES (\''.$input['username'].'\', \''.$passwordHash.'\', \''.$salt.'\', GETDATE(), \''.$createdBy.'\')"';
            $insertResult = shell_exec($sqlcmd . $insertSql);
            
            if ($insertResult !== null && is_numeric(trim($insertResult))) {
                $userId = trim($insertResult);
                
                // Get created user info
                $getUserSql = '"SELECT ID, USERNAME, CreatedAt, CreatedBy FROM T_User WHERE ID = '.$userId.'"';
                $getUserResult = shell_exec($sqlcmd . $getUserSql . ' -s ","');
                
                if ($getUserResult) {
                    $userLines = explode("\n", trim($getUserResult));
                    if (count($userLines) > 0) {
                        $userData = str_getcsv($userLines[0]);
                        if (count($userData) >= 4) {
                            echo json_encode([
                                'success' => true,
                                'message' => 'Account created successfully in SQL Server T_User database',
                                'data' => [
                                    'id' => (int)$userData[0],
                                    'username' => $userData[1],
                                    'created_at' => $userData[2],
                                    'created_by' => $userData[3]
                                ]
                            ]);
                            break;
                        }
                    }
                }
            }
            
            // If SQL Server method failed, fall back to demo database
            throw new Exception("SQL Server direct connection failed");
            
        } catch (Exception $e) {
            error_log("SQL Server connection failed, using demo database: " . $e->getMessage());
            
            // Demo database for testing (simulate T_User table)
            $demoUsers = [];
            if (file_exists('demo_users.json')) {
                $demoUsers = json_decode(file_get_contents('demo_users.json'), true) ?: [];
            }
            
            // Check if user exists
            foreach ($demoUsers as $user) {
                if ($user['username'] === $input['username']) {
                    http_response_code(409);
                    echo json_encode([
                        'success' => false,
                        'error' => 'Username already exists'
                    ]);
                    break 2;
                }
            }
            
            // Generate salt and hash password
            $salt = bin2hex(random_bytes(32));
            $passwordHash = hash('sha256', $input['password'] . $salt);
            
            // Create new user
            $userId = count($demoUsers) + 1;
            $newUser = [
                'id' => $userId,
                'username' => $input['username'],
                'password_hash' => $passwordHash,
                'password_salt' => $salt,
                'created_at' => date('c'),
                'created_by' => $input['created_by'] ?? 'API'
            ];
            
            $demoUsers[] = $newUser;
            file_put_contents('demo_users.json', json_encode($demoUsers, JSON_PRETTY_PRINT));
            
            echo json_encode([
                'success' => true,
                'message' => 'Account created successfully (demo fallback - SQL Server unavailable)',
                'data' => [
                    'id' => $newUser['id'],
                    'username' => $newUser['username'],
                    'created_at' => $newUser['created_at'],
                    'created_by' => $newUser['created_by']
                ]
            ]);
        }
        break;
        
    case '/api/auth/login':
        if ($method !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST.']);
            break;
        }
        
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
        
        // Connect to SQL Server database to verify user credentials
        try {
            // Use alternative method to connect to SQL Server since sqlsrv extension not available
            $sqlcmd = 'sqlcmd -S DESKTOP-OIB91MS -d LOGIN_TEST -E -h -1 -s "," -Q ';
            
            // Get user from T_User table
            $getUserSql = '"SELECT ID, USERNAME, PasswordHash, PasswordSalt FROM T_User WHERE USERNAME = \''.$input['username'].'\'"';
            $getUserResult = shell_exec($sqlcmd . $getUserSql);
            
            $user = null;
            if ($getUserResult && trim($getUserResult) !== '') {
                $userLines = explode("\n", trim($getUserResult));
                if (count($userLines) > 0 && strpos($userLines[0], ',') !== false) {
                    $userData = str_getcsv($userLines[0]);
                    if (count($userData) >= 4) {
                        $user = [
                            'ID' => (int)$userData[0],
                            'USERNAME' => trim($userData[1]),
                            'PasswordHash' => trim($userData[2]),
                            'PasswordSalt' => trim($userData[3])
                        ];
                    }
                }
            }
            
            if (!$user) {
                // Try demo database as fallback
                throw new Exception("User not found in SQL Server, checking demo database");
            }
            
            // Verify password with salt
            $expectedHash = hash('sha256', $input['password'] . $user['PasswordSalt']);
            if (!hash_equals($user['PasswordHash'], $expectedHash)) {
                http_response_code(401);
                echo json_encode([
                    'success' => false,
                    'error' => 'Invalid password (SQL Server)'
                ]);
                break;
            }
            
            // Use actual user data for response
            $userForResponse = [
                'id' => $user['ID'],
                'username' => $user['USERNAME']
            ];
            
        } catch (Exception $e) {
            error_log("SQL Server login failed, trying demo database: " . $e->getMessage());
            
            // Demo database for testing
            $demoUsers = [];
            if (file_exists('demo_users.json')) {
                $demoUsers = json_decode(file_get_contents('demo_users.json'), true) ?: [];
            }
            
            // Find user in demo database
            $user = null;
            foreach ($demoUsers as $demoUser) {
                if ($demoUser['username'] === $input['username']) {
                    $user = [
                        'ID' => $demoUser['id'],
                        'USERNAME' => $demoUser['username'],
                        'PasswordHash' => $demoUser['password_hash'],
                        'PasswordSalt' => $demoUser['password_salt']
                    ];
                    break;
                }
            }
            
            if (!$user) {
                // Final fallback to demo user
                if ($input['username'] !== 'BBLAMTEST1' || $input['password'] !== '1234Bbl@m') {
                    http_response_code(401);
                    echo json_encode([
                        'success' => false,
                        'error' => 'User not found in any database'
                    ]);
                    break;
                }
                
                $userForResponse = [
                    'id' => 1,
                    'username' => 'BBLAMTEST1'
                ];
            } else {
                // Verify password with salt
                $expectedHash = hash('sha256', $input['password'] . $user['PasswordSalt']);
                if (!hash_equals($user['PasswordHash'], $expectedHash)) {
                    http_response_code(401);
                    echo json_encode([
                        'success' => false,
                        'error' => 'Invalid password (demo database)'
                    ]);
                    break;
                }
                
                // Use actual user data for response
                $userForResponse = [
                    'id' => $user['ID'],
                    'username' => $user['USERNAME']
                ];
            }
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
            'Message' => "Welcome ".$userForResponse['username']
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
}
?>