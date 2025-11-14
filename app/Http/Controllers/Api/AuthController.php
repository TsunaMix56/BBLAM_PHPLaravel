<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    /**
     * Get JWT token using Basic Authentication
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function getJwtToken(Request $request)
    {
        // Extract Basic Auth credentials
        $authHeader = $request->header('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Basic ')) {
            return response()->json([
                'error' => 'Missing or invalid Authorization header. Expected Basic authentication.'
            ], 401);
        }

        // Decode Basic Auth credentials
        $encodedCredentials = substr($authHeader, 6); // Remove 'Basic ' prefix
        $decodedCredentials = base64_decode($encodedCredentials);
        
        if (!$decodedCredentials || !str_contains($decodedCredentials, ':')) {
            return response()->json([
                'error' => 'Invalid Basic authentication format.'
            ], 401);
        }

        [$username, $password] = explode(':', $decodedCredentials, 2);

        // Find user by username in T_User table
        $user = User::where('USERNAME', $username)->first();

        if (!$user || !User::verifyPassword($password, $user->PasswordHash, $user->PasswordSalt)) {
            return response()->json([
                'error' => 'Invalid credentials.'
            ], 401);
        }

        try {
            // Create JWT token with custom payload and secret
            $secretKey = config('jwt.secret', env('JWT_SECRET'));
            $payload = [
                'sub' => $user->ID,
                'username' => $user->USERNAME,
                'iat' => time(),
                'exp' => time() + (config('jwt.ttl', 60) * 60), // TTL in seconds
                'iss' => 'BBLAM-API',
                'aud' => 'BBLAM-CLIENT'
            ];
            
            $token = JWTAuth::fromUser($user, $payload);
            
            return response()->json([
                'success' => true,
                'message' => 'JWT token generated successfully',
                'data' => [
                    'access_token' => $token,
                    'token_type' => 'bearer',
                    'expires_in' => now()->addMinutes(config('jwt.ttl'))->toISOString(), // Return as datetime
                    'user' => [
                        'id' => $user->ID,
                        'username' => $user->USERNAME,
                        'created_at' => $user->CreatedAt,
                        'created_by' => $user->CreatedBy,
                    ]
                ]
            ], 200);

        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not create token'
            ], 500);
        }
    }

    /**
     * Verify JWT token with secret key
     * 
     * @param string $token
     * @return array|false
     */
    private function verifyJwtToken($token)
    {
        try {
            $secretKey = config('jwt.secret', env('JWT_SECRET'));
            
            // Manual JWT verification (for demonstration)
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return false;
            }
            
            $header = json_decode(base64_decode($parts[0]), true);
            $payload = json_decode(base64_decode($parts[1]), true);
            $signature = $parts[2];
            
            // Verify signature
            $expectedSignature = hash_hmac('sha256', $parts[0] . '.' . $parts[1], $secretKey, true);
            $expectedSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($expectedSignature));
            
            if ($signature !== $expectedSignature) {
                return false;
            }
            
            // Check expiration
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                return false;
            }
            
            return $payload;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Get user profile using JWT token
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function getProfile(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            
            if (!$user) {
                return response()->json([
                    'error' => 'User not found'
                ], 404);
            }

            return response()->json([
                'success' => true,
                'data' => [
                    'id' => $user->ID,
                    'username' => $user->USERNAME,
                    'created_at' => $user->CreatedAt,
                    'created_by' => $user->CreatedBy,
                ]
            ], 200);

        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Token is invalid or expired'
            ], 401);
        }
    }

    /**
     * Refresh JWT token
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function refreshToken(Request $request)
    {
        try {
            // Get current user from token
            $user = JWTAuth::parseToken()->authenticate();
            
            if (!$user) {
                return response()->json([
                    'error' => 'User not found'
                ], 404);
            }
            
            // Create new token with secret key
            $secretKey = config('jwt.secret', env('JWT_SECRET'));
            $payload = [
                'sub' => $user->ID,
                'username' => $user->USERNAME,
                'iat' => time(),
                'exp' => time() + (config('jwt.ttl', 60) * 60), // TTL in seconds
                'iss' => 'BBLAM-API',
                'aud' => 'BBLAM-CLIENT'
            ];
            
            $token = JWTAuth::fromUser($user, $payload);
            
            return response()->json([
                'success' => true,
                'message' => 'Token refreshed successfully',
                'data' => [
                    'access_token' => $token,
                    'token_type' => 'bearer',
                    'expires_in' => now()->addMinutes(config('jwt.ttl'))->toISOString(),
                ]
            ], 200);

        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not refresh token'
            ], 401);
        }
    }

    /**
     * Logout and invalidate token
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        try {
            JWTAuth::parseToken()->invalidate();
            
            return response()->json([
                'success' => true,
                'message' => 'Successfully logged out'
            ], 200);

        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not invalidate token'
            ], 500);
        }
    }

    /**
     * Create new user account (Requires JWT Bearer Token)
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function createAccount(Request $request)
    {
        try {
            // Verify JWT Bearer Token
            $user = JWTAuth::parseToken()->authenticate();
            
            if (!$user) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid or expired JWT token'
                ], 401);
            }

            // Validate input
            $request->validate([
                'username' => 'required|string|min:3|max:24|unique:T_User,USERNAME',
                'password' => 'required|string|min:6|max:255',
                'role' => 'nullable|string|in:user,admin,manager',
                'created_by' => 'nullable|string|max:50'
            ]);

            // Generate salt and hash password
            $salt = User::generateSalt();
            $passwordHash = User::hashPassword($request->password, $salt);

            // Create user (use authenticated user info for created_by if not provided)
            $newUser = new User();
            $newUser->USERNAME = $request->username;
            $newUser->PasswordHash = $passwordHash;
            $newUser->PasswordSalt = $salt;
            $newUser->role = $request->role ?? 'user';
            $newUser->CreatedAt = now();
            $newUser->CreatedBy = $request->created_by ?? $user->USERNAME ?? 'API';
            $newUser->save();

            return response()->json([
                'success' => true,
                'message' => 'Account created successfully',
                'data' => [
                    'id' => $newUser->ID,
                    'username' => $newUser->USERNAME,
                    'role' => $newUser->role,
                    'created_at' => $newUser->CreatedAt->toISOString(),
                    'created_by' => $newUser->CreatedBy
                ]
            ], 201);

        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Invalid or expired JWT token'
            ], 401);

        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Validation failed',
                'messages' => $e->errors()
            ], 422);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'Account creation failed',
                'message' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Login with username/password and get JWT token (Requires JWT Bearer Token)
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        try {
            // Verify JWT Bearer Token
            $authenticatedUser = JWTAuth::parseToken()->authenticate();
            
            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid or expired JWT token'
                ], 401);
            }

            // Validate input
            $request->validate([
                'username' => 'required|string',
                'password' => 'required|string'
            ]);

            // Find user by username
            $user = User::where('USERNAME', $request->username)->first();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid credentials'
                ], 401);
            }

            // Verify password
            if (!User::verifyPassword($request->password, $user->PasswordHash, $user->PasswordSalt)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid credentials'
                ], 401);
            }

           
            return response()->json([
                'success' => true,
                'message' => 'Login successful',
                'data' => [
                    'user' => [
                        'id' => $user->ID,
                        'username' => $user->USERNAME,
                        'role' => $user->role ?? 'user',
                        'created_at' => $user->CreatedAt
                    ],
                    'welcome_message' => "Welcome ".$user->USERNAME
                ]
            ], 200);

        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Validation failed',
                'messages' => $e->errors()
            ], 422);
        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'error' => 'Invalid or expired JWT token'
            ], 401);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'Login failed',
                'message' => $e->getMessage()
            ], 500);
        }
    }
}