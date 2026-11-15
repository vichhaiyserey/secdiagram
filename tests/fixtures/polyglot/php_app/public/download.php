<?php
// Legacy page script.
$file = $_GET['file'];
$lang = $_GET['lang'];

// VULNERABLE: local file inclusion.
include $lang . '.php';

// VULNERABLE: reflected XSS.
echo "Downloading " . $file;

// SAFE: escaped output.
echo htmlspecialchars($file, ENT_QUOTES);

// VULNERABLE: command injection.
system("gzip -c /srv/files/" . $file);

$ch = curl_init('https://partner.example/api');
// VULNERABLE: TLS verification disabled.
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
?>
<p>Title: <?= $_GET['title'] ?></p>
