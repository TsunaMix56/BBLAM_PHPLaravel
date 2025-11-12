# BBLAM JWT API# BBLAM JWT Authentication API



🚀 **Complete JWT Authentication API with SQL Server Integration**A PHP Laravel API that provides JWT token authentication using Basic Authentication credentials.



## Overview## Features

BBLAM JWT API เป็น RESTful API ที่ใช้ JWT Bearer Token Authentication พร้อมเชื่อมต่อกับ SQL Server Database

- JWT token generation using Basic Authentication

## Features- Token refresh functionality

- ✅ JWT Bearer Token Authentication- User profile retrieval

- ✅ SQL Server T_User Integration  - Token invalidation (logout)

- ✅ Password Salt + Hash Security- Pre-configured test user credentials

- ✅ Create Account & Login Functions

- ✅ Header Character Encoding Fix## Quick Start

- ✅ Demo Database Fallback

### Prerequisites

## Quick Start

- PHP 8.1+

### 1. Start Server- Composer

```powershell- MySQL/PostgreSQL database

.\start_api_fixed.ps1

```### Installation



### 2. Get JWT Token1. Clone the repository:

```bash```bash

POST http://localhost:8000/api/auth/tokengit clone https://github.com/TsunaMix56/BBLAM_PHPLaravel.git

Authorization: Basic QkJMQU1URVNUMToxMjM0QmJsQG0=cd BBLAM_PHPLaravel

Content-Type: application/json```

```

2. Install dependencies:

### 3. Create Account```bash

```bashcomposer install

POST http://localhost:8000/api/auth/create-account```

Authorization: Bearer YOUR_JWT_TOKEN

Content-Type: application/json3. Configure environment:

```bash

{cp .env.example .env

    "username": "newuser",# Edit .env file with your database credentials

    "password": "password123"```

}

```4. Generate application key and JWT secret:

```bash

### 4. Loginphp artisan key:generate

```bashphp artisan jwt:generate-secret

POST http://localhost:8000/api/auth/login```

Authorization: Bearer YOUR_JWT_TOKEN

Content-Type: application/json5. Run migrations and seed database:

```bash

{php artisan migrate

    "username": "test2345",php artisan db:seed

    "password": "22334455"```

}

```6. Start the development server:

```bash

## API Endpointsphp artisan serve

```

| Method | Endpoint | Description | Auth Required |

|--------|----------|-------------|---------------|## API Endpoints

| POST | `/api/auth/token` | Get JWT Token | Basic Auth |

| POST | `/api/auth/login` | User Login | JWT Bearer |### Base URL

| POST | `/api/auth/create-account` | Create Account | JWT Bearer |```

| GET | `/api/auth/profile` | Get Profile | JWT Bearer |http://localhost:8000/api

| POST | `/api/auth/refresh` | Refresh Token | JWT Bearer |```

| POST | `/api/auth/logout` | Logout | JWT Bearer |

### 1. Get JWT Token

## Authentication

**Endpoint:** `POST /auth/token`

### Basic Auth (for JWT Token)

- **Username:** `BBLAMTEST1`**Authentication:** Basic Auth

- **Password:** `1234Bbl@m`- Username: `BBLAMTEST1`

- **Encoded:** `QkJMQU1URVNUMToxMjM0QmJsQG0=`- Password: `1234Bbl@m`



### JWT Bearer Token**Request Headers:**

- All protected endpoints require: `Authorization: Bearer YOUR_JWT_TOKEN````

- Token expires in 1 hourAuthorization: Basic QkJMQU1URVNUMToxMjM0QmJsQG0=

Content-Type: application/json

## Database Integration```



### SQL Server**Example using cURL:**

- **Server:** `DESKTOP-OIB91MS````bash

- **Database:** `LOGIN_TEST`curl -X POST http://localhost:8000/api/auth/token \

- **Table:** `T_User`  -H "Authorization: Basic QkJMQU1URVNUMToxMjM0QmJsQG0=" \

- **Authentication:** Windows Authentication  -H "Content-Type: application/json"

```

### Table Structure

```sql**Response:**

T_User (```json

    ID int IDENTITY(1,1) PRIMARY KEY,{

    USERNAME nvarchar(50) NOT NULL,  "success": true,

    PasswordHash nvarchar(64) NOT NULL,  "message": "JWT token generated successfully",

    PasswordSalt nvarchar(64) NOT NULL,  "data": {

    CreatedAt datetime DEFAULT GETDATE(),    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",

    CreatedBy nvarchar(50) DEFAULT 'API'    "token_type": "bearer",

)    "expires_in": 3600,

```    "user": {

      "id": 1,

## Example Usage      "username": "BBLAMTEST1",

      "name": "BBLAM Test User",

### PowerShell Test      "email": "bblamtest1@example.com"

```powershell    }

# Get JWT Token  }

$headers = @{ Authorization = 'Basic QkJMQU1URVNUMToxMjM0QmJsQG0='; 'Content-Type' = 'application/json' }}

$token = Invoke-RestMethod -Uri "http://localhost:8000/api/auth/token" -Method POST -Headers $headers```

$jwt = $token.data.access_token

### 2. Get User Profile

# Login

$loginHeaders = @{ Authorization = "Bearer $jwt"; 'Content-Type' = 'application/json' }**Endpoint:** `GET /auth/profile`

$loginData = @{ username = "test2345"; password = "22334455" }

$result = Invoke-RestMethod -Uri "http://localhost:8000/api/auth/login" -Method POST -Headers $loginHeaders -Body ($loginData | ConvertTo-Json)**Authentication:** Bearer Token

```

**Request Headers:**

## File Structure```

Authorization: Bearer {your_jwt_token}

### Core FilesContent-Type: application/json

- `api.php` - Main API server (standalone)```

- `start_api_fixed.ps1` - Server startup script

- `composer.json` - Dependencies**Example using cURL:**

- `.env` - Environment variables```bash

curl -X GET http://localhost:8000/api/auth/profile \

### Laravel Framework  -H "Authorization: Bearer {your_jwt_token}" \

- `app/` - Laravel application files  -H "Content-Type: application/json"

- `config/` - Configuration files```

- `routes/` - Route definitions

- `vendor/` - Composer packages**Response:**

```json

## Technical Details{

  "success": true,

### Security  "data": {

- **Password Hashing:** SHA-256 with random salt    "id": 1,

- **JWT Algorithm:** HS256    "username": "BBLAMTEST1",

- **Header Cleaning:** Removes invalid characters    "name": "BBLAM Test User",

- **SQL Injection Protection:** Parameterized queries via sqlcmd    "email": "bblamtest1@example.com",

    "created_at": "2024-11-11T10:30:00.000000Z",

### Error Handling    "updated_at": "2024-11-11T10:30:00.000000Z"

- **401 Unauthorized:** Invalid credentials/token  }

- **422 Unprocessable Entity:** Validation errors}

- **409 Conflict:** Username already exists```

- **500 Internal Server Error:** Server issues

### 3. Refresh JWT Token

## Troubleshooting

**Endpoint:** `POST /auth/refresh`

### Common Issues

1. **Server won't start:** Check if port 8000 is available**Authentication:** Bearer Token

2. **JWT Token fails:** Verify Basic Auth credentials

3. **Login fails:** Check username/password and database connection**Example using cURL:**

4. **Header errors:** Ensure proper encoding in requests```bash

curl -X POST http://localhost:8000/api/auth/refresh \

### Dependencies  -H "Authorization: Bearer {your_jwt_token}" \

- **PHP 8.3.27:** Required  -H "Content-Type: application/json"

- **SQL Server:** DESKTOP-OIB91MS/LOGIN_TEST```

- **PowerShell:** For startup scripts

**Response:**

---```json

{

**Created:** November 11, 2025    "success": true,

**Version:** 1.0    "message": "Token refreshed successfully",

**Author:** BBLAM Development Team  "data": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "bearer",
    "expires_in": 3600
  }
}
```

### 4. Logout

**Endpoint:** `POST /auth/logout`

**Authentication:** Bearer Token

**Example using cURL:**
```bash
curl -X POST http://localhost:8000/api/auth/logout \
  -H "Authorization: Bearer {your_jwt_token}" \
  -H "Content-Type: application/json"
```

**Response:**
```json
{
  "success": true,
  "message": "Successfully logged out"
}
```

## Test Credentials

**Username:** `BBLAMTEST1`  
**Password:** `1234Bbl@m`

## Base64 Encoded Credentials

For Basic Auth header: `QkJMQU1URVNUMToxMjM0QmJsQG0=`

## Configuration

### JWT Settings

The JWT configuration can be adjusted in the `.env` file:

```env
JWT_SECRET=your_jwt_secret_key_here
JWT_ALGO=HS256
JWT_TTL=60  # Token lifetime in minutes
```

### Database Configuration

Configure your database connection in `.env`:

```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=bblam_db
DB_USERNAME=root
DB_PASSWORD=
```

## Error Responses

### Authentication Errors

```json
{
  "error": "Missing or invalid Authorization header. Expected Basic authentication."
}
```

```json
{
  "error": "Invalid credentials."
}
```

### Token Errors

```json
{
  "error": "Token is invalid or expired"
}
```

## Development

### Running Tests

```bash
php artisan test
```

### Code Style

```bash
php artisan pint
```

### Generate JWT Secret

```bash
php artisan jwt:generate-secret
```

## Dependencies

- Laravel 10.x
- tymon/jwt-auth 2.x
- PHP 8.1+

## License

MIT License