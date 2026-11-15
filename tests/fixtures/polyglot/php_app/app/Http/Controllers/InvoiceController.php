<?php

namespace App\Http\Controllers;

use App\Services\InvoiceService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class InvoiceController extends Controller
{
    public function __construct(private InvoiceService $invoices)
    {
    }

    // VULNERABLE: route parameter concatenated into SQL.
    public function show(Request $request, $id)
    {
        $rows = DB::select("SELECT * FROM invoices WHERE id = " . $id);
        return response()->json($rows);
    }

    // SAFE: bound parameter.
    public function find(Request $request)
    {
        return DB::select('SELECT * FROM invoices WHERE number = ?', [$request->input('number')]);
    }

    // VULNERABLE (interprocedural): controller -> InvoiceService SQL.
    public function search(Request $request)
    {
        $customer = $request->input('customer');
        return response()->json($this->invoices->searchByCustomer($customer));
    }

    // VULNERABLE: unserialize of request data.
    public function import(Request $request)
    {
        $payload = $request->input('payload');
        $data = unserialize($payload);
        return response()->json($data);
    }
}
