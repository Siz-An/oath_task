<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;


class AuthController extends Controller
{
    /**
     * Register a new user.
     */
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'confirmed', Password::defaults()],
            'role' => ['sometimes', 'string', 'in:admin,user'] // Allow role parameter during registration
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'role' => $validated['role'] ?? 'user', // Use provided role or default to 'user'
        ]);

        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        $token->save();

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user,
            'token' => [
                'access_token' => $tokenResult->accessToken,
                'token_type'   => 'Bearer',
                'expires_in'   => $token->expires_at ? now()->diffInSeconds($token->expires_at) : null,
            ],
        ], 201);
    }

    /**
     * Login user (Personal Access Token).
     */
    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        if (!Auth::attempt($request->only('email', 'password'))) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $user = Auth::user();

        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        $token->save();

        return response()->json([
            'message' => 'Login successful',
            'user' => $user,
            'token' => [
                'access_token' => $tokenResult->accessToken,
                'token_type'   => 'Bearer',
                'expires_in'   => $token->expires_at ? now()->diffInSeconds($token->expires_at) : null,
            ],
        ]);
    }

    /**
     * Login using Password Grant (Passport).
     */
    public function loginWithPasswordGrant(Request $request)
    {
        $request->validate([
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
            'client_id' => ['required', 'string'],
            'client_secret' => ['required', 'string'],
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $tokenRequest = \Illuminate\Support\Facades\Request::create(
            '/oauth/token',
            'POST',
            [
                'grant_type' => 'password',
                'client_id' => $request->client_id,
                'client_secret' => $request->client_secret,
                'username' => $request->email,
                'password' => $request->password,
                'scope' => '',
            ]
        );

        $response = app()->handle($tokenRequest);
        $content = $response->getContent();
        $tokenData = json_decode($content, true);
        
        if ($response->getStatusCode() !== 200) {
            return response()->json($tokenData, $response->getStatusCode());
        }
        
        return response()->json([
            'message' => 'Login successful',
            'user' => $user,
            'token' => [
                'access_token' => $tokenData['access_token'],
                'refresh_token' => $tokenData['refresh_token'],
                'token_type' => $tokenData['token_type'],
                'expires_in' => $tokenData['expires_in'],
            ],
        ]);
    }


    /**
     * Refresh access token.
     */
    public function refreshToken(Request $request): JsonResponse
    {
        $request->validate([
            'refresh_token' => ['required', 'string'],
            'client_id' => ['required', 'string'],
            'client_secret' => ['required', 'string'],
        ]);

        // Create a request to Passport's token endpoint for refresh
        $tokenRequest = \Illuminate\Support\Facades\Request::create(
            '/oauth/token',
            'POST',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $request->refresh_token,
                'client_id' => $request->client_id,
                'client_secret' => $request->client_secret,
                'scope' => '',
            ]
        );

        $response = app()->handle($tokenRequest);
        
        // Convert the response to JsonResponse
        $content = $response->getContent();
        $data = json_decode($content, true);
        
        return response()->json($data, $response->getStatusCode());
    }

    /**
     * Get authenticated user.
     */
    public function user(Request $request): JsonResponse
    {
        return response()->json([
            'user' => $request->user(),
        ]);
    }

    /**
     * Logout current device.
     */
    public function logout(Request $request): JsonResponse
    {
        $token = $request->user()->currentAccessToken();
        if ($token) {
            $token->revoke();
        }

        return response()->json([
            'message' => 'Successfully logged out',
        ]);
    }

    /**
     * Logout from all devices.
     */
    public function logoutAll(Request $request): JsonResponse
    {
        $request->user()->tokens()->each(fn ($token) => $token->revoke());

        return response()->json([
            'message' => 'Successfully logged out from all devices',
        ]);
    }
}

