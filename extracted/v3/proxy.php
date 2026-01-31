<?php
/**
 * XC BulkOps - F5 XC API Proxy
 * 
 * This proxy handles all API requests to F5 Distributed Cloud,
 * bypassing browser CORS restrictions.
 * 
 * Security Features:
 * - Only allows requests to F5 XC domains
 * - Validates required parameters
 * - Sanitizes input
 * - No credentials stored server-side
 */

// Set CORS headers to allow requests from any origin
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Access-Control-Max-Age: 86400'); // 24 hours cache for preflight

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Set JSON content type for all responses
header('Content-Type: application/json');

// Only allow POST requests for proxy operations
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'error' => 'Method not allowed',
        'message' => 'Only POST requests are accepted'
    ]);
    exit();
}

// Get request body
$requestBody = file_get_contents('php://input');
$request = json_decode($requestBody, true);

// Validate JSON parsing
if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode([
        'error' => 'Invalid JSON',
        'message' => 'Request body must be valid JSON'
    ]);
    exit();
}

// Validate required fields
$requiredFields = ['method', 'tenant', 'path', 'apiToken'];
$missingFields = [];

foreach ($requiredFields as $field) {
    if (empty($request[$field])) {
        $missingFields[] = $field;
    }
}

if (!empty($missingFields)) {
    http_response_code(400);
    echo json_encode([
        'error' => 'Missing required fields',
        'fields' => $missingFields
    ]);
    exit();
}

// Extract and sanitize request parameters
$method = strtoupper(trim($request['method']));
$tenant = preg_replace('/[^a-zA-Z0-9\-_]/', '', $request['tenant']); // Sanitize tenant name
$path = $request['path'];
$apiToken = $request['apiToken'];
$body = isset($request['body']) ? $request['body'] : null;

// Validate HTTP method
$allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
if (!in_array($method, $allowedMethods)) {
    http_response_code(400);
    echo json_encode([
        'error' => 'Invalid HTTP method',
        'allowed' => $allowedMethods
    ]);
    exit();
}

// Validate tenant name format
if (strlen($tenant) < 2 || strlen($tenant) > 64) {
    http_response_code(400);
    echo json_encode([
        'error' => 'Invalid tenant name',
        'message' => 'Tenant name must be between 2 and 64 characters'
    ]);
    exit();
}

// Build target URL - only allow F5 XC domains
$targetUrl = "https://{$tenant}.console.ves.volterra.io{$path}";

// Validate the URL is going to F5 XC
$parsedUrl = parse_url($targetUrl);
if (!$parsedUrl || !isset($parsedUrl['host'])) {
    http_response_code(400);
    echo json_encode([
        'error' => 'Invalid URL',
        'message' => 'Could not parse target URL'
    ]);
    exit();
}

// Strict domain validation - only allow F5 XC domains
$allowedDomainPattern = '/^[a-zA-Z0-9\-_]+\.console\.ves\.volterra\.io$/';
if (!preg_match($allowedDomainPattern, $parsedUrl['host'])) {
    http_response_code(403);
    echo json_encode([
        'error' => 'Domain not allowed',
        'message' => 'Only F5 XC domains (*.console.ves.volterra.io) are permitted'
    ]);
    exit();
}

// Initialize cURL
$ch = curl_init();

// Set cURL options
curl_setopt_array($ch, [
    CURLOPT_URL => $targetUrl,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 5,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_CUSTOMREQUEST => $method,
    CURLOPT_HTTPHEADER => [
        'Authorization: APIToken ' . $apiToken,
        'Content-Type: application/json',
        'Accept: application/json',
        'User-Agent: XC-BulkOps-Proxy/1.0'
    ],
    CURLOPT_HEADER => true // Include response headers
]);

// Add request body for POST/PUT/PATCH
if (in_array($method, ['POST', 'PUT', 'PATCH']) && $body !== null) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
}

// Execute request
$response = curl_exec($ch);
$error = curl_error($ch);
$errno = curl_errno($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

curl_close($ch);

// Handle cURL errors
if ($errno) {
    http_response_code(502);
    echo json_encode([
        'error' => 'Proxy request failed',
        'message' => $error,
        'code' => $errno
    ]);
    exit();
}

// Separate headers and body
$responseHeaders = substr($response, 0, $headerSize);
$responseBody = substr($response, $headerSize);

// Set the HTTP status code from the upstream response
http_response_code($httpCode);

// Output the response body
echo $responseBody;