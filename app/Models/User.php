<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'T_User';

    /**
     * The primary key associated with the table.
     *
     * @var string
     */
    protected $primaryKey = 'ID';

    /**
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'USERNAME',
        'PasswordHash',
        'PasswordSalt',
        'role',
        'CreatedAt',
        'CreatedBy',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'PasswordHash',
        'PasswordSalt',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'CreatedAt' => 'datetime',
    ];

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
            'username' => $this->USERNAME,
        ];
    }

    /**
     * Generate a salt for password hashing
     *
     * @return string
     */
    public static function generateSalt()
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Hash password with salt
     *
     * @param string $password
     * @param string $salt
     * @return string
     */
    public static function hashPassword($password, $salt)
    {
        return hash('sha256', $password . $salt);
    }

    /**
     * Verify password against hash and salt
     *
     * @param string $password
     * @param string $hash
     * @param string $salt
     * @return bool
     */
    public static function verifyPassword($password, $hash, $salt)
    {
        return hash_equals($hash, self::hashPassword($password, $salt));
    }
}