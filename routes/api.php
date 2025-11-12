<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Public routes
Route::post('/auth/token', [AuthController::class, 'getJwtToken'])->name('auth.token');

// Protected routes (require JWT authentication)
Route::middleware(['auth:api'])->group(function () {
    Route::get('/auth/profile', [AuthController::class, 'getProfile'])->name('auth.profile');
    Route::post('/auth/refresh', [AuthController::class, 'refreshToken'])->name('auth.refresh');
    Route::post('/auth/logout', [AuthController::class, 'logout'])->name('auth.logout');
    Route::post('/auth/create-account', [AuthController::class, 'createAccount'])->name('auth.create-account');
    Route::post('/auth/login', [AuthController::class, 'login'])->name('auth.login');
});