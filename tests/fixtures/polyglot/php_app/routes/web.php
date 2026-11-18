<?php

use App\Http\Controllers\InvoiceController;
use Illuminate\Support\Facades\Route;

Route::get('/invoices/{id}', [InvoiceController::class, 'show']);
Route::post('/invoices/import', [InvoiceController::class, 'import']);
Route::get('/invoices/search', [InvoiceController::class, 'search']);
Route::get('/status', function () {
    return 'ok';
});
