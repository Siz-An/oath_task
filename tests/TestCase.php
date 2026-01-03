<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Laravel\Passport\Client;
use Illuminate\Support\Str;

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
        
        // Ensure personal access client exists
        $this->artisan('passport:client', [
            '--personal' => true,
            '--name' => 'Test Personal Access Client',
            '--provider' => 'users',
        ]);
    }

    /**
     * Create a personal access client for tests.
     */
    protected function ensurePersonalAccessClient()
    {
        // Check if any personal access client exists (clients with null owner and specific name pattern)
        $existingPersonalClient = Client::whereNull('owner_id')
            ->where('name', 'Laravel Personal Access Client')
            ->first();

        if (!$existingPersonalClient) {
            // Create the personal access client using Passport's expected format
            $client = new Client();
            $client->id = (string) Str::orderedUuid();
            $client->name = 'Laravel Personal Access Client';
            $client->secret = null; // Personal access clients don't have secrets
            $client->redirect_uris = 'http://localhost';
            $client->provider = 'users'; // Set the provider to match what Passport is looking for
            $client->grant_types = '[]'; // Initialize as empty JSON array
            $client->revoked = false;
            $client->save();
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
                'redirect_uris' => 'http://localhost',
                'grant_types' => '["client_credentials","personal_access"]',
                'provider' => null,
                'secret' => encrypt('test-secret'),
                'revoked' => false,
                'owner_id' => null,
                'owner_type' => null,
            ]
        );

        return Passport::actingAsClient($client, $scopes);
    }
}