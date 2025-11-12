<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return response()->json([
        'message' => 'BBLAM JWT Authentication API',
        'version' => '1.0.0',
        'endpoints' => [
            'POST /api/auth/token' => 'Get JWT token using Basic Auth',
            'GET /api/auth/profile' => 'Get user profile (requires JWT token)',
            'POST /api/auth/refresh' => 'Refresh JWT token',
            'POST /api/auth/logout' => 'Logout and invalidate token'
        ]
    ]);
});