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
use Laravel\Passport\TokenRepository;
use Laravel\Passport\RefreshTokenRepository;

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

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        // Generate token using Passport
        $tokenResult = $user->createToken('Password Grant Token', []);
        $token = $tokenResult->token;
        $token->save();

        return response()->json([
            'message' => 'Login successful',
            'user' => $user,
            'token' => [
                'access_token' => $tokenResult->accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $token->expires_at ? $token->expires_at->diffInSeconds(now()) : null,
            ],
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
        
        $refreshTokenRepo = app(RefreshTokenRepository::class);
        $token = $refreshTokenRepo->get($request->refresh_token);
        
        if (!$token || $token->isExpired()) {
            return response()->json([
                'message' => 'Invalid or expired refresh token',
            ], 401);
        }
        
        $user = User::find($token->user_id);
        if (!$user) {
            return response()->json([
                'message' => 'User not found',
            ], 401);
        }
        
        // Revoke the old refresh token
        $refreshTokenRepo->revokeRefreshToken($request->refresh_token);
        
        // Create a new token
        $tokenResult = $user->createToken('Access Token', []);
        $newToken = $tokenResult->token;
        $newToken->save();
        
        return response()->json([
            'message' => 'Token refreshed successfully',
            'token' => [
                'access_token' => $tokenResult->accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $newToken->expires_at ? $newToken->expires_at->diffInSeconds(now()) : null,
            ],
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
