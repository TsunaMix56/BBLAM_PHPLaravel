<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        User::create([
            'name' => 'BBLAM Test User',
            'username' => 'BBLAMTEST1',
            'email' => 'bblamtest1@example.com',
            'password' => Hash::make('1234Bbl@m'),
        ]);
    }
}