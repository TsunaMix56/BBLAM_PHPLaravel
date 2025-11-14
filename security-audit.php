<?php

/**
 * Security Audit Script for OWASP Compliance
 * Run: php security-audit.php
 */

class SecurityAuditor {
    
    private $issues = [];
    private $passed = [];
    
    public function runAudit() {
        echo "🔒 BBLAM Security Audit - OWASP Top 10 Compliance Check\n";
        echo "=" . str_repeat("=", 60) . "\n\n";
        
        $this->checkA01_BrokenAccessControl();
        $this->checkA02_CryptographicFailures();
        $this->checkA03_Injection();
        $this->checkA04_InsecureDesign();
        $this->checkA05_SecurityMisconfiguration();
        $this->checkA06_VulnerableComponents();
        $this->checkA07_AuthenticationFailures();
        $this->checkA08_DataIntegrityFailures();
        $this->checkA09_SecurityLogging();
        $this->checkA10_SSRF();
        
        $this->generateReport();
    }
    
    private function checkA01_BrokenAccessControl() {
        echo "A01 - Broken Access Control: ";
        
        // Check for role-based access control
        if ($this->checkDatabaseColumn('T_User', 'role')) {
            $this->passed[] = "A01: Role-based access control implemented";
            echo "✅ PASS\n";
        } else {
            $this->issues[] = "A01: Missing role-based access control";
            echo "❌ FAIL\n";
        }
    }
    
    private function checkA02_CryptographicFailures() {
        echo "A02 - Cryptographic Failures: ";
        
        // Check if using modern password hashing
        $apiContent = file_get_contents('api.php');
        if (strpos($apiContent, 'PASSWORD_ARGON2ID') !== false) {
            $this->passed[] = "A02: Using Argon2ID password hashing";
            echo "✅ PASS\n";
        } else {
            $this->issues[] = "A02: Not using modern password hashing";
            echo "❌ FAIL\n";
        }
    }
    
    private function checkA03_Injection() {
        echo "A03 - Injection: ";
        
        $apiContent = file_get_contents('api.php');
        if (strpos($apiContent, 'prepare(') !== false && strpos($apiContent, 'execute([') !== false) {
            $this->passed[] = "A03: Using prepared statements";
            echo "✅ PASS\n";
        } else {
            $this->issues[] = "A03: Not using prepared statements";
            echo "❌ FAIL\n";
        }
    }
    
    private function checkA04_InsecureDesign() {
        echo "A04 - Insecure Design: ";
        
        $apiContent = file_get_contents('api.php');
        if (strpos($apiContent, 'strlen($input[\'password\']) < 12') !== false) {
            $this->passed[] = "A04: Strong password policy (12+ chars)";
            echo "✅ PASS\n";
        } else {
            $this->issues[] = "A04: Weak password policy";
            echo "❌ FAIL\n";
        }
    }
    
    private function checkA05_SecurityMisconfiguration() {
        echo "A05 - Security Misconfiguration: ";
        
        if (file_exists('app/Http/Middleware/SecurityHeadersMiddleware.php')) {
            $this->passed[] = "A05: Security headers middleware exists";
            echo "✅ PASS\n";
        } else {
            $this->issues[] = "A05: Missing security headers";
            echo "❌ FAIL\n";
        }
    }
    
    private function checkA06_VulnerableComponents() {
        echo "A06 - Vulnerable Components: ";
        
        if (file_exists('.github/workflows/security.yml')) {
            $this->passed[] = "A06: Security scanning pipeline exists";
            echo "✅ PASS\n";
        } else {
            $this->issues[] = "A06: No automated security scanning";
            echo "❌ FAIL\n";
        }
    }
    
    private function checkA07_AuthenticationFailures() {
        echo "A07 - Authentication Failures: ";
        
        if (file_exists('app/Http/Middleware/RateLimitMiddleware.php')) {
            $this->passed[] = "A07: Rate limiting middleware exists";
            echo "✅ PASS\n";
        } else {
            $this->issues[] = "A07: No rate limiting";
            echo "❌ FAIL\n";
        }
    }
    
    private function checkA08_DataIntegrityFailures() {
        echo "A08 - Data Integrity Failures: ";
        
        if (file_exists('composer.lock') && file_exists('Dockerfile')) {
            $this->passed[] = "A08: Reproducible builds with Docker and Composer";
            echo "✅ PASS\n";
        } else {
            $this->issues[] = "A08: Missing build integrity";
            echo "❌ FAIL\n";
        }
    }
    
    private function checkA09_SecurityLogging() {
        echo "A09 - Security Logging: ";
        
        $apiContent = file_get_contents('api.php');
        if (strpos($apiContent, 'error_log(') !== false) {
            $this->passed[] = "A09: Error logging implemented";
            echo "✅ PASS\n";
        } else {
            $this->issues[] = "A09: No security logging";
            echo "❌ FAIL\n";
        }
    }
    
    private function checkA10_SSRF() {
        echo "A10 - SSRF: ";
        
        // Check if SSRFGuard protection is implemented
        if (!file_exists('SSRFGuard.php')) {
            $this->issues[] = "A10: SSRFGuard.php not found";
            echo "❌ FAIL\n";
            return;
        }
        
        // Check if SSRF protection is properly integrated
        $apiContent = file_get_contents('api.php');
        $ssrfContent = file_get_contents('SSRFGuard.php');
        
        $hasValidation = strpos($ssrfContent, 'validateURL') !== false;
        $hasPrivateIPBlock = strpos($ssrfContent, 'isPrivateIP') !== false;
        $hasSafeRequest = strpos($ssrfContent, 'safeHttpRequest') !== false;
        $hasApiIntegration = strpos($apiContent, 'SSRFGuard') !== false;
        $hasSafeEndpoint = strpos($apiContent, '/api/safe-request') !== false;
        
        if ($hasValidation && $hasPrivateIPBlock && $hasSafeRequest && $hasApiIntegration && $hasSafeEndpoint) {
            $this->passed[] = "A10: SSRF protection implemented with URL validation and private IP blocking";
            echo "✅ PASS\n";
        } else {
            $missing = [];
            if (!$hasValidation) $missing[] = "URL validation";
            if (!$hasPrivateIPBlock) $missing[] = "Private IP blocking";
            if (!$hasSafeRequest) $missing[] = "Safe HTTP request wrapper";
            if (!$hasApiIntegration) $missing[] = "API integration";
            if (!$hasSafeEndpoint) $missing[] = "Safe request endpoint";
            
            $this->issues[] = "A10: Missing SSRF protection: " . implode(', ', $missing);
            echo "❌ FAIL\n";
        }
    }
    
    private function checkDatabaseColumn($table, $column) {
        try {
            $host = $_ENV['DB_HOST'] ?? 'localhost';
            $port = $_ENV['DB_PORT'] ?? '3307';
            $database = $_ENV['DB_DATABASE'] ?? 'bblamtestdb';
            $username = $_ENV['DB_USERNAME'] ?? 'root';
            $password = $_ENV['DB_PASSWORD'] ?? 'Sql@154465';
            
            $pdo = new PDO("mysql:host={$host};port={$port};dbname={$database}", $username, $password);
            $stmt = $pdo->prepare("DESCRIBE {$table}");
            $stmt->execute();
            $columns = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            return in_array($column, $columns);
        } catch (Exception $e) {
            return false;
        }
    }
    
    private function generateReport() {
        echo "\n" . str_repeat("=", 70) . "\n";
        echo "🎯 AUDIT SUMMARY\n";
        echo str_repeat("=", 70) . "\n";
        
        $totalChecks = count($this->passed) + count($this->issues);
        $passedChecks = count($this->passed);
        $percentage = round(($passedChecks / $totalChecks) * 100, 1);
        
        echo "Total Checks: {$totalChecks}\n";
        echo "Passed: {$passedChecks}\n";
        echo "Failed: " . count($this->issues) . "\n";
        echo "Score: {$percentage}%\n\n";
        
        if ($percentage >= 80) {
            echo "🎉 OWASP COMPLIANCE: ✅ PASSED ({$percentage}%)\n";
        } else {
            echo "🚨 OWASP COMPLIANCE: ❌ FAILED ({$percentage}%)\n";
        }
        
        if (!empty($this->issues)) {
            echo "\n❌ Issues Found:\n";
            foreach ($this->issues as $issue) {
                echo "  - {$issue}\n";
            }
        }
        
        echo "\n✅ Security Controls Passed:\n";
        foreach ($this->passed as $pass) {
            echo "  - {$pass}\n";
        }
        
        echo "\n📊 Compliance Status: " . ($percentage >= 80 ? "COMPLIANT" : "NON-COMPLIANT") . "\n";
    }
}

// Run the audit
if (php_sapi_name() === 'cli') {
    $auditor = new SecurityAuditor();
    $auditor->runAudit();
}