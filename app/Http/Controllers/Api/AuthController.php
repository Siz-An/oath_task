<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     * Register a new user.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'confirmed', Password::defaults()],
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        // Generate personal access token for the new user
        $tokenResult = $user->createToken('Personal Access Token');
        $accessToken = $tokenResult->accessToken;
        $expiresAt = $tokenResult->getToken() ? $tokenResult->getToken()->expires_at : null;

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user,
            'token' => [
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_at' => $expiresAt,
            ],
        ], 201);
    }

    /**
     * Login user using personal access token.
     *
     * @param Request $request
     * @return JsonResponse
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

        // Revoke all existing tokens (optional - for single device login)
        // $user->tokens()->delete();

        // Generate new personal access token
        $tokenResult = $user->createToken('Personal Access Token');
        $accessToken = $tokenResult->accessToken;
        $expiresAt = $tokenResult->getToken() ? $tokenResult->getToken()->expires_at : null;

        return response()->json([
            'message' => 'Login successful',
            'user' => $user,
            'token' => [
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_at' => $expiresAt,
            ],
        ]);
    }

    /**
     * Login user using Password Grant (OAuth 2.0).
     * This method uses the password grant client to issue tokens.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function loginWithPasswordGrant(Request $request): JsonResponse
    {
        $request->validate([
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        // Make request to Passport's token endpoint
        $response = Http::asForm()->post(url('/oauth/token'), [
            'grant_type' => 'password',
            'client_id' => config('passport.password_grant_client.id'),
            'client_secret' => config('passport.password_grant_client.secret'),
            'username' => $request->email,
            'password' => $request->password,
            'scope' => '',
        ]);

        if ($response->failed()) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $user = User::where('email', $request->email)->first();

        return response()->json([
            'message' => 'Login successful',
            'user' => $user,
            'token' => $response->json(),
        ]);
    }

    /**
     * Refresh access token using refresh token.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function refreshToken(Request $request): JsonResponse
    {
        $request->validate([
            'refresh_token' => ['required', 'string'],
        ]);

        $response = Http::asForm()->post(url('/oauth/token'), [
            'grant_type' => 'refresh_token',
            'refresh_token' => $request->refresh_token,
            'client_id' => config('passport.password_grant_client.id'),
            'client_secret' => config('passport.password_grant_client.secret'),
            'scope' => '',
        ]);

        if ($response->failed()) {
            return response()->json([
                'message' => 'Could not refresh token',
                'error' => $response->json(),
            ], 401);
        }

        return response()->json([
            'message' => 'Token refreshed successfully',
            'token' => $response->json(),
        ]);
    }

    /**
     * Get authenticated user details.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function user(Request $request): JsonResponse
    {
        return response()->json([
            'user' => $request->user(),
        ]);
    }

    /**
     * Logout user and revoke current access token.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function logout(Request $request): JsonResponse
    {

        // Revoke the current access token (Passport v13+)
        $token = $request->user()->currentAccessToken();
        if ($token) {
            $token->revoke();
        }

        return response()->json([
            'message' => 'Successfully logged out',
        ]);
    }

    /**
     * Logout from all devices by revoking all tokens.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function logoutAll(Request $request): JsonResponse
    {
        // Revoke all tokens for the user
        $request->user()->tokens()->each(function ($token) {
            $token->revoke();
        });

        return response()->json([
            'message' => 'Successfully logged out from all devices',
        ]);
    }
}
