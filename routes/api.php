<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group.
|
*/

// Public routes (no authentication required)
Route::prefix('auth')->group(function () {
    // User registration
    Route::post('/register', [AuthController::class, 'register']);
    
    // Login with personal access token
    Route::post('/login', [AuthController::class, 'login']);
    
    // Login with password grant (OAuth 2.0)
    Route::post('/login/oauth', [AuthController::class, 'loginWithPasswordGrant']);
    
    // Refresh token
    Route::post('/refresh', [AuthController::class, 'refreshToken']);
});

// Protected routes (authentication required)
Route::middleware('auth:api')->group(function () {
    // Auth routes
    Route::prefix('auth')->group(function () {
        // Get authenticated user
        Route::get('/user', [AuthController::class, 'user']);
        
        // Logout (revoke current token)
        Route::post('/logout', [AuthController::class, 'logout']);
        
        // Logout from all devices (revoke all tokens)
        Route::post('/logout-all', [AuthController::class, 'logoutAll']);
    });

    // Add your protected API routes here
    // Example:
    // Route::apiResource('posts', PostController::class);
});
