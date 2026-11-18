<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/reports')]
class ReportController extends AbstractController
{
    #[Route('/{name}', name: 'report_show', methods: ['GET'])]
    public function show(string $name): Response
    {
        // VULNERABLE: path traversal.
        return new Response(file_get_contents('/var/reports/' . $name));
    }
}
