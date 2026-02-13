<?php
/**
 * Pure PHP JWT Authentication Include File
 *
 * For use in non-Laravel applications
 *
 * INSTALLATION:
 * 1. composer require firebase/php-jwt
 * 2. composer require symfony/dotenv (for .env support)
 *
 * USAGE:
 * <?php
 * require_once 'auth-include-pure-php.php';
 *
 * // Now use helper functions:
 * getCurrentUser();
 * getUserEmail();
 * getUserRole();
 * isAdmin();
 * isSuperAdmin();
 * ?>
 */

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Load environment variables from .env file
if (file_exists(__DIR__ . '/../../.env')) {
    $dotenv = new \Symfony\Component\Dotenv\Dotenv();
    $dotenv->load(__DIR__ . '/../../.env');
}

// Get JWT secret from environment
$jwtSecret = $_ENV['JWT_SECRET'] ?? getenv('JWT_SECRET');
$mainDomain = $_ENV['MAIN_DOMAIN'] ?? getenv('MAIN_DOMAIN') ?? 'https://alertaraqc.com';

if (!$jwtSecret) {
    die('JWT_SECRET not configured in environment');
}

// Debug logging
$debugLog = [];
$debugLog[] = '=== JWT AUTHENTICATION DEBUG (PURE PHP) ===';
$debugLog[] = 'Current URL: ' . getCurrentRequestUrl();
$debugLog[] = 'Current Time: ' . date('Y-m-d H:i:s');
$debugLog[] = 'Session started: YES';

// Step 1: Get JWT token from multiple sources
$token = null;
$user = null;

// Try URL query parameter first (initial redirect from login)
if (isset($_GET['token']) && !empty($_GET['token'])) {
    $token = $_GET['token'];
    $debugLog[] = '✓ Token found in URL (?token parameter)';
    $debugLog[] = 'Token Preview: ' . substr($token, 0, 50) . '...';

    // Store in session for subsequent requests
    $_SESSION['jwt_token'] = $token;
    $debugLog[] = '✓ Token stored in session';
    $debugLog[] = 'Session ID: ' . session_id();
} else {
    // Try to get from session for subsequent requests
    if (isset($_SESSION['jwt_token'])) {
        $token = $_SESSION['jwt_token'];
        $debugLog[] = '✓ Token retrieved from session';
        $debugLog[] = 'Token Preview: ' . substr($token, 0, 50) . '...';
    } else {
        $debugLog[] = '✗ No token found in URL or session';
    }
}

// Step 2: Try Authorization header as fallback
if (!$token) {
    $authHeader = getAuthorizationHeader();
    if ($authHeader && strpos($authHeader, 'Bearer ') === 0) {
        $token = substr($authHeader, 7);
        $debugLog[] = '✓ Token found in Authorization header';
        $debugLog[] = 'Token Preview: ' . substr($token, 0, 50) . '...';
    } else {
        $debugLog[] = '✗ No Authorization header found';
    }
}

// Step 3: Validate JWT token
if ($token) {
    $debugLog[] = '🔐 Validating JWT token...';

    try {
        // Decode JWT token using firebase/php-jwt
        $decoded = \Firebase\JWT\JWT::decode($token, new \Firebase\JWT\Key($jwtSecret, 'HS256'));

        if ($decoded) {
            // Extract user data from JWT payload
            $user = [
                'sub' => $decoded->sub ?? null,
                'id' => $decoded->sub ?? null,
                'email' => $decoded->email ?? '',
                'department' => $decoded->department ?? '',
                'role' => $decoded->role ?? 'admin',
                'iat' => $decoded->iat ?? time(),
                'exp' => $decoded->exp ?? (time() + 3600)
            ];

            $debugLog[] = '✓ JWT token validated successfully!';
            $debugLog[] = 'User ID: ' . ($user['id'] ?? 'N/A');
            $debugLog[] = 'User Email: ' . ($user['email'] ?? 'N/A');
            $debugLog[] = 'Department: ' . ($user['department'] ?? 'N/A');
            $debugLog[] = 'Role: ' . ($user['role'] ?? 'N/A');
            $debugLog[] = 'Expires: ' . date('Y-m-d H:i:s', $user['exp'] ?? time());
        }
    } catch (\Exception $e) {
        $debugLog[] = '✗ JWT token validation FAILED!';
        $debugLog[] = 'Error: ' . $e->getMessage();
        error_log('JWT Validation Error: ' . $e->getMessage());
    }
} else {
    $debugLog[] = '✗ No token available for validation';
}

// Log debug information
foreach ($debugLog as $log) {
    error_log($log);
}

// Step 4: Redirect if not authenticated
if (!$user) {
    $debugLog[] = '';
    $debugLog[] = '❌ AUTHENTICATION FAILED - REDIRECTING';
    $debugLog[] = 'Redirect URL: ' . $mainDomain;
    $debugLog[] = '=====================================';

    foreach ($debugLog as $log) {
        error_log($log);
    }

    header('Location: ' . $mainDomain);
    exit;
}

// Step 5: Check token expiration
if ($user['exp'] && $user['exp'] < time()) {
    error_log('JWT token expired for user: ' . $user['email']);
    unset($_SESSION['jwt_token']);
    header('Location: ' . $mainDomain);
    exit;
}

// Step 6: Authentication successful
$debugLog[] = '';
$debugLog[] = '✅ AUTHENTICATION SUCCESSFUL';
$debugLog[] = '=====================================';
foreach ($debugLog as $log) {
    error_log($log);
}

// Step 7: Make user data globally available
$GLOBALS['authenticated_user'] = $user;

// Department name mapping
$departmentNames = [
    'law_enforcement_department' => 'Law Enforcement Department',
    'traffic_and_transport_department' => 'Traffic & Transport Department',
    'fire_and_rescue_department' => 'Fire & Rescue Department',
    'emergency_response_department' => 'Emergency Response Department',
    'community_policing_department' => 'Community Policing Department',
    'crime_data_department' => 'Crime Data Analytics Department',
    'public_safety_department' => 'Public Safety Department',
    'health_and_safety_department' => 'Health & Safety Department',
    'disaster_preparedness_department' => 'Disaster Preparedness Department',
    'emergency_communication_department' => 'Emergency Communication Department',
];

// ============================================
// Helper Functions
// ============================================

/**
 * Get current authenticated user
 */
function getCurrentUser()
{
    return $GLOBALS['authenticated_user'] ?? null;
}

/**
 * Get user role
 */
function getUserRole()
{
    return $GLOBALS['authenticated_user']['role'] ?? 'guest';
}

/**
 * Get user email
 */
function getUserEmail()
{
    return $GLOBALS['authenticated_user']['email'] ?? '';
}

/**
 * Get user ID
 */
function getUserId()
{
    return $GLOBALS['authenticated_user']['id'] ?? null;
}

/**
 * Get user department code
 */
function getUserDepartment()
{
    return $GLOBALS['authenticated_user']['department'] ?? '';
}

/**
 * Get human-readable department name
 */
function getDepartmentName()
{
    static $names = [
        'law_enforcement_department' => 'Law Enforcement Department',
        'traffic_and_transport_department' => 'Traffic & Transport Department',
        'fire_and_rescue_department' => 'Fire & Rescue Department',
        'emergency_response_department' => 'Emergency Response Department',
        'community_policing_department' => 'Community Policing Department',
        'crime_data_department' => 'Crime Data Analytics Department',
        'public_safety_department' => 'Public Safety Department',
        'health_and_safety_department' => 'Health & Safety Department',
        'disaster_preparedness_department' => 'Disaster Preparedness Department',
        'emergency_communication_department' => 'Emergency Communication Department',
    ];

    $dept = getUserDepartment();
    return $names[$dept] ?? ucfirst(str_replace('_', ' ', $dept));
}

/**
 * Check if user is super admin
 */
function isSuperAdmin()
{
    return getUserRole() === 'super_admin';
}

/**
 * Check if user is admin
 */
function isAdmin()
{
    return getUserRole() === 'admin';
}

/**
 * Get logout URL
 */
function getLogoutUrl()
{
    return 'https://login.alertaraqc.com?action=logout';
}

/**
 * Handle logout action
 */
function logout()
{
    unset($_SESSION['jwt_token']);
    session_destroy();
    header('Location: https://login.alertaraqc.com');
    exit;
}

// Auto logout if requested
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    logout();
}

// ============================================
// Utility Functions
// ============================================

/**
 * Get current request URL
 */
function getCurrentRequestUrl()
{
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? 'https://' : 'http://';
    return $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
}

/**
 * Get Authorization header
 */
function getAuthorizationHeader()
{
    $headers = null;

    if (function_exists('apache_request_headers')) {
        $headers = apache_request_headers();
    } else {
        foreach ($_SERVER as $key => $value) {
            if (substr($key, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(str_replace('_', ' ', substr($key, 5))))] = $value;
            }
        }
    }

    return $headers['Authorization'] ?? null;
}

/**
 * Get JavaScript to store user data in localStorage
 */
function getTokenRefreshScript()
{
    $user = getCurrentUser();
    $exp = $user['exp'] ?? 0;

    ob_start();
    ?>
    <script>
        // Token expiration check
        const tokenExpiresAt = <?php echo ($exp * 1000); ?>;

        const checkTokenExpiration = () => {
            if (Date.now() >= tokenExpiresAt) {
                alert('Your session has expired. Please login again.');
                window.location.href = 'https://login.alertaraqc.com';
            }
        };

        // Check every minute
        setInterval(checkTokenExpiration, 60000);
        checkTokenExpiration();

        // Store user data in localStorage
        const userData = <?php echo json_encode($user); ?>;
        localStorage.setItem('user_data', JSON.stringify(userData));
    </script>
    <?php
    return ob_get_clean();
}

?>
