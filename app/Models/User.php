<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Laravel\Passport\HasApiTokens;
use Illuminate\Support\Str;

class User extends Authenticatable
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasFactory, Notifiable, HasApiTokens;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'role',
        'temp_token',
        'temp_token_expires_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    /**
     * Get the posts for the user.
     */
    public function posts(): HasMany
    {
        return $this->hasMany(\App\Models\Post::class);
    }

    /**
     * Generate a temporary token for passwordless login
     */
    public function generateTempToken(): string
    {
        $token = Str::random(60);
        
        $this->update([
            'temp_token' => hash('sha256', $token),
            'temp_token_expires_at' => now()->addMinutes(30), // Token expires in 30 minutes
        ]);
        
        return $token;
    }

    /**
     * Send a magic link to the user for passwordless login
     */
    public function sendMagicLink(): void
    {
        $token = $this->generateTempToken();
        
        // In a real application, you would send an email with the magic link
        // For example: Mail::to($this->email)->send(new MagicLinkMail($this, $token));
        
        // For demo purposes, we're just returning the token
        // In production, you'd want to actually send an email
    }

    /**
     * Validate a temporary token for passwordless login
     */
    public static function validateTempToken(string $token): ?self
    {
        $hashedToken = hash('sha256', $token);
        
        $user = static::where('temp_token', $hashedToken)
                     ->where('temp_token_expires_at', '>', now())
                     ->first();
        
        if ($user) {
            // Clear the token after successful validation
            $user->update([
                'temp_token' => null,
                'temp_token_expires_at' => null,
            ]);
        }
        
        return $user;
    }
}
