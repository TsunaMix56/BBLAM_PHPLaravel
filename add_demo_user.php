<?php
// Generate test2345 user with password 1234
$salt = bin2hex(random_bytes(32));
$hash = hash('sha256', '1234' . $salt);

$user = [
    'id' => 2,
    'username' => 'test2345',
    'password_hash' => $hash,
    'password_salt' => $salt,
    'created_at' => date('c'),
    'created_by' => 'API'
];

// Read existing users
$existingUsers = json_decode(file_get_contents('demo_users.json'), true);

// Add new user
$existingUsers[] = $user;

// Write back
file_put_contents('demo_users.json', json_encode($existingUsers, JSON_PRETTY_PRINT));

echo "✅ User test2345 added to demo_users.json\n";
echo "Username: test2345\n";
echo "Password: 1234\n";
echo "Hash: $hash\n";
echo "Salt: $salt\n";
