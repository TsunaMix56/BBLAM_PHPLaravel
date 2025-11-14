<?php

class SecurityValidator 
{
    /**
     * Strong password validation
     */
    public static function validatePassword($password) {
        $errors = [];
        
        // Minimum 12 characters
        if (strlen($password) < 12) {
            $errors[] = 'Password must be at least 12 characters long';
        }
        
        // Must contain uppercase
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter';
        }
        
        // Must contain lowercase  
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter';
        }
        
        // Must contain numbers
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one number';
        }
        
        // Must contain special characters
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character';
        }
        
        // Check against common passwords
        $commonPasswords = [
            'password123', 'admin123', '123456789', 'qwerty123',
            'password!', 'letmein123', 'welcome123', 'admin@123'
        ];
        
        if (in_array(strtolower($password), array_map('strtolower', $commonPasswords))) {
            $errors[] = 'Password is too common, please choose a more secure password';
        }
        
        return empty($errors) ? true : $errors;
    }
    
    /**
     * Validate username format
     */
    public static function validateUsername($username) {
        $errors = [];
        
        // Length check (3-30 characters)
        if (strlen($username) < 3 || strlen($username) > 30) {
            $errors[] = 'Username must be between 3 and 30 characters';
        }
        
        // Alphanumeric + underscore only
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            $errors[] = 'Username can only contain letters, numbers, and underscores';
        }
        
        // Must start with letter
        if (!preg_match('/^[a-zA-Z]/', $username)) {
            $errors[] = 'Username must start with a letter';
        }
        
        // Reserved usernames
        $reserved = ['admin', 'root', 'system', 'api', 'test', 'guest', 'anonymous'];
        if (in_array(strtolower($username), $reserved)) {
            $errors[] = 'Username is reserved and cannot be used';
        }
        
        return empty($errors) ? true : $errors;
    }
    
    /**
     * Rate limiting by IP and user
     */
    public static function checkRateLimit($key, $maxAttempts = 5, $timeWindow = 900) {
        $cacheKey = "rate_limit:" . $key;
        $attempts = apcu_fetch($cacheKey) ?: 0;
        
        if ($attempts >= $maxAttempts) {
            $ttl = apcu_fetch($cacheKey . "_ttl") ?: time();
            $remaining = $timeWindow - (time() - $ttl);
            
            if ($remaining > 0) {
                return [
                    'allowed' => false,
                    'retry_after' => $remaining,
                    'attempts' => $attempts
                ];
            } else {
                // Reset counter after time window
                apcu_delete($cacheKey);
                apcu_delete($cacheKey . "_ttl");
                $attempts = 0;
            }
        }
        
        // Increment counter
        apcu_store($cacheKey, $attempts + 1, $timeWindow);
        if ($attempts === 0) {
            apcu_store($cacheKey . "_ttl", time(), $timeWindow);
        }
        
        return [
            'allowed' => true,
            'remaining' => max(0, $maxAttempts - $attempts - 1),
            'attempts' => $attempts + 1
        ];
    }
}