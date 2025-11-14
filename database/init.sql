-- MySQL Database Initialization Script
-- Create T_User table for BBLAM Laravel Application

USE bblamtestdb;

-- Create T_User table with same schema as SQL Server version
CREATE TABLE IF NOT EXISTS T_User (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert demo user: test2345 with password 1234
-- Password: SHA256('1234' + salt)
-- Salt: randomsalt123
INSERT INTO T_User (username, password_hash, salt) VALUES 
('test2345', SHA2(CONCAT('1234', 'randomsalt123'), 256), 'randomsalt123')
ON DUPLICATE KEY UPDATE 
password_hash = SHA2(CONCAT('1234', 'randomsalt123'), 256),
salt = 'randomsalt123';

-- Insert additional demo user for testing
INSERT INTO T_User (username, password_hash, salt) VALUES 
('admin', SHA2(CONCAT('admin123', 'adminsalt456'), 256), 'adminsalt456')
ON DUPLICATE KEY UPDATE 
password_hash = SHA2(CONCAT('admin123', 'adminsalt456'), 256),
salt = 'adminsalt456';

-- Display created users
SELECT id, username, created_at FROM T_User;