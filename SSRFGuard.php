<?php
/**
 * SSRF (Server-Side Request Forgery) Protection Class
 * Protects against A10: Server-Side Request Forgery vulnerabilities
 */
class SSRFGuard {
    
    // Private IP ranges to block
    private static $privateCIDRs = [
        '127.0.0.0/8',     // Localhost
        '10.0.0.0/8',      // Private class A
        '172.16.0.0/12',   // Private class B
        '192.168.0.0/16',  // Private class C
        '169.254.0.0/16',  // Link local
        '::1/128',         // IPv6 localhost
        'fc00::/7',        // IPv6 unique local
        'fe80::/10',       // IPv6 link local
    ];
    
    // Blocked ports (common internal services)
    private static $blockedPorts = [
        22,    // SSH
        23,    // Telnet
        25,    // SMTP
        53,    // DNS
        110,   // POP3
        143,   // IMAP
        993,   // IMAPS
        995,   // POP3S
        3306,  // MySQL
        5432,  // PostgreSQL
        6379,  // Redis
        9200,  // Elasticsearch
        27017, // MongoDB
    ];
    
    /**
     * Validate URL to prevent SSRF attacks
     */
    public static function validateURL($url) {
        if (empty($url)) {
            return false;
        }
        
        // Parse the URL
        $parsedUrl = parse_url($url);
        if (!$parsedUrl || !isset($parsedUrl['scheme']) || !isset($parsedUrl['host'])) {
            return false;
        }
        
        // Only allow HTTP/HTTPS
        if (!in_array($parsedUrl['scheme'], ['http', 'https'])) {
            return false;
        }
        
        // Check port restrictions
        $port = $parsedUrl['port'] ?? ($parsedUrl['scheme'] === 'https' ? 443 : 80);
        if (in_array($port, self::$blockedPorts)) {
            return false;
        }
        
        // Resolve hostname to IP
        $ip = gethostbyname($parsedUrl['host']);
        if ($ip === $parsedUrl['host']) {
            // If gethostbyname fails, it returns the hostname
            // This could be a non-resolvable hostname
            return false;
        }
        
        // Check if IP is private/internal
        if (self::isPrivateIP($ip)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Check if IP is in private/internal range
     */
    private static function isPrivateIP($ip) {
        foreach (self::$privateCIDRs as $cidr) {
            if (self::ipInRange($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if IP is in CIDR range
     */
    private static function ipInRange($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }
        
        list($subnet, $mask) = explode('/', $cidr);
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // IPv6 handling
            return self::ipv6InRange($ip, $subnet, $mask);
        }
        
        // IPv4 handling
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $maskLong = -1 << (32 - $mask);
        
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }
    
    /**
     * IPv6 range checking
     */
    private static function ipv6InRange($ip, $subnet, $mask) {
        $ipBinary = inet_pton($ip);
        $subnetBinary = inet_pton($subnet);
        
        if ($ipBinary === false || $subnetBinary === false) {
            return false;
        }
        
        $bytesToCheck = intval($mask / 8);
        $bitsInLastByte = $mask % 8;
        
        // Check full bytes
        for ($i = 0; $i < $bytesToCheck; $i++) {
            if ($ipBinary[$i] !== $subnetBinary[$i]) {
                return false;
            }
        }
        
        // Check remaining bits in the last byte
        if ($bitsInLastByte > 0) {
            $maskByte = 0xFF << (8 - $bitsInLastByte);
            if ((ord($ipBinary[$bytesToCheck]) & $maskByte) !== (ord($subnetBinary[$bytesToCheck]) & $maskByte)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Safe HTTP request with SSRF protection
     */
    public static function safeHttpRequest($url, $options = []) {
        if (!self::validateURL($url)) {
            throw new Exception('URL blocked by SSRF protection');
        }
        
        // Default cURL options with security settings
        $defaultOptions = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false, // Don't follow redirects
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'BBLAM-SecureClient/1.0',
        ];
        
        $curlOptions = $options + $defaultOptions;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt_array($ch, $curlOptions);
        
        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        
        curl_close($ch);
        
        if ($result === false) {
            throw new Exception('HTTP request failed: ' . $error);
        }
        
        return [
            'body' => $result,
            'http_code' => $httpCode,
        ];
    }
}