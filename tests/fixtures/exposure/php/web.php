<?php

Route::get('/home', function () {
    return 'home';
});

Route::middleware(['auth:sanctum'])->group(function () {
    Route::get('/account', function () {
        return 'account';
    });
});

Route::get('/billing', function () {
    return 'billing';
})->middleware('auth');
