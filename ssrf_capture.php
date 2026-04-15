<?php
/**
 * SSRF Capture Script for Twilio Proof-of-Concept
 * Saves all incoming requests to log file for bug bounty evidence
 * 
 * Author: Luciole (Assistant) for Mickaël "Pahpah" Couclet
 * Date: 2026-04-15
 */

// Configuration
$LOG_FILE = 'ssrf_twilio_log.txt';
$MAX_LOG_SIZE = 1024 * 1024; // 1MB max
$ALLOWED_IPS = []; // Empty = allow all (for testing)
$ENABLE_LOGGING = true;

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Function to log request
function log_request($log_file) {
    global $MAX_LOG_SIZE;
    
    // Prepare log entry
    $timestamp = date('Y-m-d H:i:s');
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $method = $_SERVER['REQUEST_METHOD'] ?? 'unknown';
    
    $log_entry = "=" . str_repeat("=", 60) . "\n";
    $log_entry .= "TIMESTAMP: $timestamp\n";
    $log_entry .= "CLIENT IP: $client_ip\n";
    $log_entry .= "METHOD: $method\n";
    $log_entry .= "URL: {$_SERVER['REQUEST_URI'] ?? '/'}\n";
    $log_entry .= "USER AGENT: $user_agent\n";
    
    // Headers
    $log_entry .= "HEADERS:\n";
    foreach (getallheaders() as $name => $value) {
        $log_entry .= "  $name: $value\n";
    }
    
    // GET parameters
    if (!empty($_GET)) {
        $log_entry .= "GET PARAMETERS:\n";
        foreach ($_GET as $key => $value) {
            $log_entry .= "  $key: " . htmlspecialchars($value) . "\n";
        }
    }
    
    // POST parameters (if any)
    if ($method === 'POST') {
        $log_entry .= "POST DATA:\n";
        if (!empty($_POST)) {
            foreach ($_POST as $key => $value) {
                $log_entry .= "  $key: " . htmlspecialchars($value) . "\n";
            }
        } else {
            // Raw POST data
            $raw_post = file_get_contents('php://input');
            if (!empty($raw_post)) {
                $log_entry .= "  RAW: " . htmlspecialchars(substr($raw_post, 0, 1000)) . "\n";
            }
        }
    }
    
    // Server variables (for debugging)
    $log_entry .= "SERVER INFO:\n";
    $log_entry .= "  PHP_SELF: {$_SERVER['PHP_SELF']}\n";
    $log_entry .= "  HTTP_HOST: {$_SERVER['HTTP_HOST'] ?? 'unknown'}\n";
    $log_entry .= "  REQUEST_TIME: {$_SERVER['REQUEST_TIME']}\n";
    
    // Check if it's a Twilio request
    $is_twilio = false;
    if (strpos($user_agent, 'TwilioProxy') !== false || 
        strpos($user_agent, 'Twilio') !== false ||
        isset($_GET['CallSid']) || 
        isset($_POST['CallSid'])) {
        $is_twilio = true;
        $log_entry .= "TWILIO DETECTED: YES\n";
    } else {
        $log_entry .= "TWILIO DETECTED: NO\n";
    }
    
    // Rotate log if too large
    if (file_exists($log_file) && filesize($log_file) > $MAX_LOG_SIZE) {
        $backup_file = $log_file . '.' . date('Ymd-His');
        rename($log_file, $backup_file);
    }
    
    // Write to log
    file_put_contents($log_file, $log_entry, FILE_APPEND);
    
    return $is_twilio;
}

// Main execution
if ($ENABLE_LOGGING) {
    $is_twilio = log_request($LOG_FILE);
    
    // Response based on request type
    if ($is_twilio) {
        // For Twilio, return valid TwiML response
        header('Content-Type: text/xml');
        echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
        echo '<Response>' . "\n";
        echo '  <Say voice="alice">SSRF test successful. Request logged.</Say>' . "\n";
        echo '  <Pause length="1"/>' . "\n";
        echo '  <Hangup/>' . "\n";
        echo '</Response>' . "\n";
    } else {
        // For browser/curl, show simple message
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html>' . "\n";
        echo '<html lang="en">' . "\n";
        echo '<head>' . "\n";
        echo '  <meta charset="UTF-8">' . "\n";
        echo '  <title>SSRF Capture Endpoint</title>' . "\n";
        echo '  <style>' . "\n";
        echo '    body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }' . "\n";
        echo '    .success { color: green; font-weight: bold; }' . "\n";
        echo '    .info { background: #f0f0f0; padding: 15px; border-radius: 5px; }' . "\n";
        echo '  </style>' . "\n";
        echo '</head>' . "\n";
        echo '<body>' . "\n";
        echo '  <h1>SSRF Capture Endpoint</h1>' . "\n";
        echo '  <p class="success">✅ Request captured successfully!</p>' . "\n";
        echo '  <div class="info">' . "\n";
        echo '    <p><strong>Timestamp:</strong> ' . date('Y-m-d H:i:s') . '</p>' . "\n";
        echo '    <p><strong>Client IP:</strong> ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . '</p>' . "\n";
        echo '    <p><strong>User Agent:</strong> ' . ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown') . '</p>' . "\n";
        echo '    <p><strong>Log file:</strong> ' . realpath($LOG_FILE) . '</p>' . "\n";
        echo '  </div>' . "\n";
        echo '  <p>This endpoint is used to capture SSRF requests for bug bounty testing.</p>' . "\n";
        echo '</body>' . "\n";
        echo '</html>' . "\n";
    }
} else {
    // Logging disabled
    header('HTTP/1.1 403 Forbidden');
    echo 'Logging disabled';
}

// Also log to error_log for additional capture
error_log("SSRF Capture: Request from {$_SERVER['REMOTE_ADDR']} with UA: {$_SERVER['HTTP_USER_AGENT']}");
?>