<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;

/*
|--------------------------------------------------------------------------
| Console Routes
|--------------------------------------------------------------------------
|
| This file is where you may define all of your Closure based console
| commands. Each Closure is bound to a command instance allowing a
| simple approach to interacting with each command's IO methods.
|
*/

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

Artisan::command('jwt:generate-secret', function () {
    $secret = base64_encode(random_bytes(32));
    $this->info("JWT Secret: " . $secret);
    $this->info("Add this to your .env file:");
    $this->info("JWT_SECRET=" . $secret);
})->purpose('Generate a JWT secret key');