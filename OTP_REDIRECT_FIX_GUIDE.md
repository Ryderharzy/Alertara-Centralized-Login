# OTP Redirect Issue - Complete Fix Guide

## Problem Summary
After successful OTP verification, users are redirected back to the login page (index) instead of their department-specific dashboard page.

## Root Cause
The department-specific subdomain pages are **not including the `auth-include.php` file**, which is responsible for:
1. Accepting JWT tokens from the URL (`?token=xxx`)
2. Validating the JWT token
3. Setting up authenticated user data
4. Redirecting unauthenticated users back to the login page

## Authentication Flow

### What's Working ✅
1. User enters email/password → OTP generated
2. User enters OTP → Verified successfully
3. AuthController generates redirect URL: `https://crime-analytics.alertaraqc.com/dashboard.php?token={JWT_TOKEN}`
4. Frontend redirects user to that URL

### What's Broken ❌
5. Department subdomain page (`dashboard.php`) is called
6. **Page doesn't include `auth-include.php`** → No user authentication
7. Page redirects to MAIN_DOMAIN (login page) because user is not authenticated

## Solution: Update Department Dashboard Files

Each department subdomain needs a dashboard file that includes the `auth-include.php` file.

### Step 1: Understand the Directory Structure

**On login.alertaraqc.com:** (Current Laravel app)
```
examples/
└── auth-include.php  ← This file validates JWT tokens
```

**On each department subdomain:** (e.g., crime-analytics.alertaraqc.com)
```
dashboard.php         ← Must include auth-include.php
law-dashboard.php
traffic-dashboard.php
... etc
```

### Step 2: Create Dashboard Files with Auth Include

For **crime-analytics.alertaraqc.com/dashboard.php**:
```php
<?php
// MUST be at the very top of the file
require_once './auth-include.php';

// Now you have access to authenticated user data:
// Variables: $userId, $userEmail, $userDepartment, $userRole, $departmentName
// Functions: getCurrentUser(), getUserEmail(), getUserRole(), getDepartmentName(), isSuperAdmin(), isAdmin()

$user = getCurrentUser();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Crime Data Analytics Dashboard</title>
</head>
<body>
    <h1>Welcome, <?php echo htmlspecialchars($user['email']); ?>!</h1>
    <p>Department: <?php echo htmlspecialchars(getDepartmentName()); ?></p>
    <p>Role: <?php echo htmlspecialchars(getUserRole()); ?></p>

    <?php echo getTokenRefreshScript(); ?>
</body>
</html>
```

### Step 3: Copy Structure to All Department Subdomains

For each subdomain, create the dashboard file that includes `auth-include.php`:

```
law-enforcement.alertaraqc.com/law-dashboard.php
traffic.alertaraqc.com/traffic-dashboard.php
fire.alertaraqc.com/fire-dashboard.php
emergency.alertaraqc.com/emergency-dashboard.php
community.alertaraqc.com/community-dashboard.php
crime-analytics.alertaraqc.com/dashboard.php       ← Fixed extension in AuthController
public-safety.alertaraqc.com/public-safety-dashboard.php
health-safety.alertaraqc.com/health-dashboard.php
disaster.alertaraqc.com/disaster-dashboard.php
emergency-comm.alertaraqc.com/comm-dashboard.php
```

Each file must start with:
```php
<?php
require_once './auth-include.php';
// ... rest of dashboard code
```

### Step 4: Copy auth-include.php to All Subdomains

You need to copy the `examples/auth-include.php` file to each department subdomain so it's available for inclusion.

For example:
```
crime-analytics.alertaraqc.com/
├── auth-include.php        ← Copy from examples/
├── dashboard.php           ← Include auth-include.php
└── vendor/                 ← PHP dependencies for JWT
```

### Available User Data After Including auth-include.php

After `require_once './auth-include.php';`, you have access to:

**Global Variables:**
- `$userId` - User ID
- `$userEmail` - User email
- `$userDepartment` - Department code (e.g., 'crime_data_department')
- `$userRole` - Role ('admin' or 'super_admin')
- `$departmentName` - Human-readable department name
- `$currentSubdomain` - Current subdomain (e.g., 'crime-analytics')
- `$exp` - Token expiration timestamp
- `$GLOBALS['authenticated_user']` - Complete user object

**Helper Functions:**
```php
getCurrentUser()        // Returns complete user array
getUserRole()          // Returns 'admin' or 'super_admin'
getUserEmail()         // Returns user email
getUserDepartment()    // Returns department code
getDepartmentName()    // Returns readable department name
isSuperAdmin()         // Returns true if user is super_admin
isAdmin()              // Returns true if user is admin
isLaravelEnv()         // Returns true if running in Laravel
getLogoutUrl()         // Returns logout URL
getMainDomain()        // Returns main domain
getTokenRefreshScript()// Returns JavaScript for token expiration check
```

### Step 5: Nginx Configuration for Subdomains

Make sure each subdomain is configured to serve PHP files properly. Example for crime-analytics.alertaraqc.com:

```nginx
server {
    server_name crime-analytics.alertaraqc.com;
    listen 443 ssl http2;

    root /var/www/alertara/crime-analytics;
    index dashboard.php;

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    # Fallback to index.php for routing
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
}
```

## Testing the Fix

1. **Start login process:**
   - Go to `https://login.alertaraqc.com/`
   - Enter valid credentials
   - Enter OTP code

2. **Verify redirect:**
   - Should be redirected to `https://crime-analytics.alertaraqc.com/dashboard.php?token=...`
   - Token should be visible in browser's developer tools (Network tab)

3. **Verify authentication:**
   - Page should load with user data displayed
   - If no auth-include.php: Redirects back to login page
   - If auth-include.php included: Shows authenticated content

## Files Modified

- ✅ `app/Http/Controllers/AuthController.php:350` - Fixed missing `.php` extension
  - Changed: `'crime_data_department' => 'dashboard',`
  - To: `'crime_data_department' => 'dashboard.php',`

## Files to Create/Update

- [ ] `crime-analytics.alertaraqc.com/dashboard.php` - Include auth-include.php
- [ ] `law-enforcement.alertaraqc.com/law-dashboard.php` - Include auth-include.php
- [ ] `traffic.alertaraqc.com/traffic-dashboard.php` - Include auth-include.php
- [ ] `fire.alertaraqc.com/fire-dashboard.php` - Include auth-include.php
- [ ] All other department subdomains (see step 3)
- [ ] Copy `auth-include.php` to all subdomain root directories

## Debugging

If redirect still doesn't work:

1. **Check browser console** - Look for JavaScript errors
2. **Check Network tab** - Verify redirect URL in response
3. **Check page source** - Verify auth-include.php is included
4. **Check server logs** - Look for PHP errors
5. **Verify token in URL** - Token should be in query string: `?token=xxx`
6. **Test JWT validation** - Token should decode without errors

## Important Notes

- `auth-include.php` expects token from `$_GET['token']` on first load
- It then stores token in `$_SESSION['jwt_token']` for subsequent requests
- Token expires based on JWT expiration time (configurable)
- If token expires, user is redirected to `MAIN_DOMAIN`
