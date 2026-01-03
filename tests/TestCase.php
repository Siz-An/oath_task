<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Laravel\Passport\Client;

abstract class TestCase extends BaseTestCase
{
    use CreatesApplication;
    use RefreshDatabase;

    /**
     * Set up the test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Install Passport keys if they are not already installed
        if (!file_exists(storage_path('oauth-private.key'))) {
            $this->artisan('passport:install', ['--force' => true]);
        }
    }

    /**
     * Helper to act as a user for API tests.
     */
    protected function actingAsUser($user = null, array $scopes = [])
    {
        $user = $user ?: \App\Models\User::factory()->create();
        Passport::actingAs($user, $scopes);

        return $user;
    }

    /**
     * Helper to act as a client for Passport password grant testing.
     */
    protected function actingAsClient(array $scopes = [])
    {
        // Create a personal access client if none exists
        $client = Client::firstOrCreate(
            ['name' => 'Test Client'],
            [
                'redirect_uris' => ['http://localhost'],
                'grant_types' => ['client_credentials', 'personal_access'],
                'provider' => null,
                'secret' => encrypt('test-secret'),
                'revoked' => false,
            ]
        );

        return Passport::actingAsClient($client, $scopes);
    }
}
