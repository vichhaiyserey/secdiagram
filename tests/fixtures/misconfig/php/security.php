<?php

class VerifyCsrfToken
{
    // VULNERABLE: CSRF disabled for every route.
    protected $except = ['*'];
}

// VULNERABLE: any origin + credentials.
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true');

// VULNERABLE: session cookie readable by scripts.
ini_set('session.cookie_httponly', '0');

// VULNERABLE: entity expansion enabled.
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT);

// VULNERABLE: predictable password reset token.
$resetToken = md5(uniqid());

// SAFE: CSPRNG.
$sessionToken = bin2hex(random_bytes(32));
