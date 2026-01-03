<?php

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class LoginApiTest extends TestCase
{
    use RefreshDatabase;

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_login_successfully()
    {
        $user = User::factory()->create([
            'email' => 'testlogin@example.com',
            'password' => bcrypt('password123'),
        ]);

        $response = $this->postJson('/api/auth/login', [
            'email' => 'testlogin@example.com',
            'password' => 'password123',
        ]);

        $response
            ->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'user' => [
                    'id',
                    'name',
                    'email',
                    'role',
                ],
                'token' => [
                    'access_token',
                    'token_type',
                    'expires_in',
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function login_fails_with_wrong_credentials()
    {
        $user = User::factory()->create([
            'email' => 'testwrong@example.com',
            'password' => bcrypt('password123'),
        ]);

        $response = $this->postJson('/api/auth/login', [
            'email' => 'testwrong@example.com',
            'password' => 'wrongpassword',
        ]);

        $response
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }
}
