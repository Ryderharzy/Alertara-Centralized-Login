<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class CentralizedAdminUser extends Authenticatable implements JWTSubject
{
    use HasFactory, Notifiable;

    protected $table = 'centralized_admin_user';

    protected $fillable = [
        'email',
        'password_hash',
        'department',
        'role',
        'ip_address',
        'attempt_count',
        'unlock_token',
        'unlock_token_expiry',
        'last_login',
        'last_activity',
    ];

    protected $hidden = [
        'password_hash',
        'unlock_token',
    ];

    protected $casts = [
        'last_login' => 'datetime',
        'last_activity' => 'datetime',
        'unlock_token_expiry' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public function getAuthPassword()
    {
        return $this->password_hash;
    }

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [
            'department' => $this->department,
            'role' => $this->role,
            'email' => $this->email
        ];
    }
}
