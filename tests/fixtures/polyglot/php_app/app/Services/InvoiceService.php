<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class InvoiceService
{
    public function searchByCustomer(string $customer)
    {
        return DB::select("SELECT * FROM invoices WHERE customer = '" . $customer . "'");
    }
}
