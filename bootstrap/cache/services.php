<?php return array (
  'providers' => 
  array (
    0 => 'Laravel\\Sail\\SailServiceProvider',
    1 => 'Laravel\\Sanctum\\SanctumServiceProvider',
    2 => 'Laravel\\Tinker\\TinkerServiceProvider',
    3 => 'Carbon\\Laravel\\ServiceProvider',
    4 => 'NunoMaduro\\Collision\\Adapters\\Laravel\\CollisionServiceProvider',
    5 => 'Termwind\\Laravel\\TermwindServiceProvider',
    6 => 'Spatie\\LaravelIgnition\\IgnitionServiceProvider',
    7 => 'Tymon\\JWTAuth\\Providers\\LaravelServiceProvider',
    8 => 'Tymon\\JWTAuth\\Providers\\LaravelServiceProvider',
  ),
  'eager' => 
  array (
    0 => 'Laravel\\Sanctum\\SanctumServiceProvider',
    1 => 'Carbon\\Laravel\\ServiceProvider',
    2 => 'NunoMaduro\\Collision\\Adapters\\Laravel\\CollisionServiceProvider',
    3 => 'Termwind\\Laravel\\TermwindServiceProvider',
    4 => 'Spatie\\LaravelIgnition\\IgnitionServiceProvider',
    5 => 'Tymon\\JWTAuth\\Providers\\LaravelServiceProvider',
    6 => 'Tymon\\JWTAuth\\Providers\\LaravelServiceProvider',
  ),
  'deferred' => 
  array (
    'Laravel\\Sail\\Console\\InstallCommand' => 'Laravel\\Sail\\SailServiceProvider',
    'Laravel\\Sail\\Console\\PublishCommand' => 'Laravel\\Sail\\SailServiceProvider',
    'command.tinker' => 'Laravel\\Tinker\\TinkerServiceProvider',
  ),
  'when' => 
  array (
    'Laravel\\Sail\\SailServiceProvider' => 
    array (
    ),
    'Laravel\\Tinker\\TinkerServiceProvider' => 
    array (
    ),
  ),
);