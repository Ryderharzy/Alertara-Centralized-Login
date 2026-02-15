# 🔐 Centralized Login Integration Guide

> How to integrate **AlerTara Centralized Login System** into your dashboard using JWT authentication

---

## 📋 Quick Navigation

| Framework | Quick Start |
|-----------|------------|
| **🔴 Laravel** | [Laravel Integration](#-laravel-integration) |
| **🟡 Pure PHP** | [Pure PHP Integration](#-pure-php-integration) |
| **⚡ API Endpoint** | [Using API Endpoint](#-using-api-endpoint-recommended) |

---

## ⚡ Using API Endpoint (Recommended)

> **This is the MODERN and RECOMMENDED approach!** Use the JWT validation API endpoint instead of including files.

### What is the API Endpoint?

The centralized login system provides an **HTTP API endpoint** that validates JWT tokens and returns user data:

```
GET https://login.alertaraqc.com/api/auth/validate?token=YOUR_JWT_TOKEN
```

**Benefits:**
- ✅ No files to copy or maintain
- ✅ Works with any framework (Laravel, Pure PHP, Node.js, etc.)
- ✅ Decoupled and scalable
- ✅ Token hidden from URL immediately
- ✅ Works cross-domain

### API Endpoint Documentation

**Endpoint:** `GET /api/auth/validate`

**Accepts token from:**
1. Query parameter: `?token=eyJ0...`
2. Authorization header: `Authorization: Bearer eyJ0...`
3. Custom header: `X-Access-Token: eyJ0...`
4. Session: `$_SESSION['jwt_token']`

**Response:**
```json
{
  "authenticated": true,
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "department": "law_enforcement_department",
    "department_name": "Law Enforcement Department",
    "role": "super_admin",
    "exp": 1705123456
  }
}
```

**Error Response:**
```json
{
  "authenticated": false,
  "message": "Invalid token"
}
```

### Quick Start: Pure PHP Example

**Create: `dashboard.php`**

```php
<?php
// 1️⃣ Capture token from URL
$token = $_GET['token'] ?? $_SESSION['jwt_token'] ?? '';

if ($token) {
    $_SESSION['jwt_token'] = $token;
}

// 2️⃣ Check if user has token
if (!isset($_SESSION['jwt_token'])) {
    header('Location: https://login.alertaraqc.com');
    exit;
}

// 3️⃣ Validate token via API endpoint
$ch = curl_init('https://login.alertaraqc.com/api/auth/validate');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Bearer ' . $_SESSION['jwt_token'],
    'Accept: application/json'
]);

$response = json_decode(curl_exec($ch), true);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 4️⃣ Check if authenticated
if ($httpCode !== 200 || !$response['authenticated']) {
    session_destroy();
    header('Location: https://login.alertaraqc.com');
    exit;
}

// 5️⃣ Extract user data
$currentUser = $response['user'];
?>

<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <!-- Hide token from URL -->
    <script>
        if (window.location.search.includes('token=')) {
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    </script>

    <!-- Display user info in header -->
    <header>
        <h1>Dashboard</h1>
        <div class="user-info">
            <span>Email: <?= htmlspecialchars($currentUser['email']) ?></span>
            <span>Role: <?= htmlspecialchars($currentUser['role']) ?></span>
            <span>Department: <?= htmlspecialchars($currentUser['department_name']) ?></span>
            <button onclick="logout()">Logout</button>
        </div>
    </header>

    <!-- Your content here -->
    <main>
        <h2>Welcome to Dashboard</h2>
    </main>

    <script>
        function logout() {
            window.location.href = 'https://login.alertaraqc.com/logout';
        }
    </script>
</body>
</html>
```

### Quick Start: Fetch API Example

**Using JavaScript to call the API:**

```javascript
// Get token from URL or session
const token = new URLSearchParams(window.location.search).get('token')
    || sessionStorage.getItem('jwt_token');

// Call API endpoint
fetch('https://login.alertaraqc.com/api/auth/validate?token=' + token)
    .then(res => res.json())
    .then(data => {
        if (data.authenticated) {
            console.log('User:', data.user);
            console.log('Email:', data.user.email);
            console.log('Role:', data.user.role);
            console.log('Department:', data.user.department_name);

            // Update header with user info
            document.querySelector('header').innerHTML = `
                Welcome ${data.user.email} | ${data.user.role} | ${data.user.department_name}
            `;
        } else {
            window.location.href = 'https://login.alertaraqc.com';
        }
    });
```

### Environment Variables for API Endpoint

**For Pure PHP (.env):**

```env
# Centralized Login API
CENTRALIZED_LOGIN_URL=https://login.alertaraqc.com
API_VALIDATE_ENDPOINT=https://login.alertaraqc.com/api/auth/validate

# Session
SESSION_DOMAIN=.alertaraqc.com
SESSION_LIFETIME=120
SESSION_SECURE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
```

**For Laravel (.env):**

```env
# Database (LGU)
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=LGU
DB_USERNAME=(PROVIDED BY ADMIN)
DB_PASSWORD=(PROVIDED BY ADMIN)

# JWT
JWT_SECRET=(PROVIDED BY ADMIN)
JWT_ALGO=HS256
JWT_TTL=60

# Centralized Login
MAIN_DOMAIN=https://alertaraqc.com
CENTRALIZED_LOGIN_URL=https://login.alertaraqc.com
API_VALIDATE_ENDPOINT=https://login.alertaraqc.com/api/auth/validate

# Session Configuration
SESSION_DRIVER=file
SESSION_LIFETIME=120
SESSION_DOMAIN=.alertaraqc.com
SESSION_PATH=/
SESSION_SECURE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
```

### Comparison: Include File vs API Endpoint

| Aspect | Include File | API Endpoint |
|--------|--------------|--------------|
| **Setup** | Copy file to project | Just call HTTP endpoint |
| **Maintenance** | Update file when needed | No maintenance needed |
| **Framework** | Works anywhere | Works anywhere |
| **Performance** | Fast (local) | HTTP call (~50-100ms) |
| **Scalability** | Limited | Highly scalable |
| **Security** | Good | Excellent |
| **Recommended** | Legacy approach | ✅ Modern approach |

---

## 🎯 What is This?

This guide helps you integrate the **centralized login system** into your **dashboard subdomain** (e.g., `crime-analytics.alertaraqc.com`).

### How It Works

```
User logs in at login.alertaraqc.com
            ↓
   OTP verification
            ↓
   JWT token generated
            ↓
   System checks user DEPARTMENT
            ↓
   Routes to correct SUBDOMAIN
            ↓
   Redirect with token
            ↓
   Your dashboard validates token
            ↓
   User authenticated ✅
```

### 🌐 Subdomain Routing

The centralized login system **automatically redirects users** to their department's subdomain:

```
Department → Subdomain
─────────────────────────────────────
crime_data_department → crime-analytics.alertaraqc.com
law_enforcement_department → law-enforcement.alertaraqc.com
fire_and_rescue_department → fire.alertaraqc.com
traffic_and_transport_department → traffic.alertaraqc.com
emergency_response_department → emergency.alertaraqc.com
community_policing_department → community.alertaraqc.com
... and more
```

#### 📝 How the Redirection Code Works

**File: `app/Http/Controllers/AuthController.php`**

```php
// Department to Subdomain Mapping
$departmentSubdomains = [
    'law_enforcement_department' => 'law-enforcement',
    'traffic_and_transport_department' => 'traffic',
    'fire_and_rescue_department' => 'fire',
    'emergency_response_department' => 'emergency',
    'community_policing_department' => 'community',
    'crime_data_department' => 'crime-analytics',
    'public_safety_department' => 'public-safety',
    'health_and_safety_department' => 'health',
    'disaster_preparedness_department' => 'disaster',
    'emergency_communication_department' => 'comm',
];

// Get subdomain for user's department
$subdomain = $departmentSubdomains[$user->department] ?? 'dashboard';

// Get dashboard file for that department
$dashboardFiles = [
    'law_enforcement_department' => 'law-dashboard.php',
    'traffic_and_transport_department' => 'traffic-dashboard.php',
    'fire_and_rescue_department' => 'fire-dashboard.php',
    'emergency_response_department' => 'emergency-dashboard.php',
    'community_policing_department' => 'community-dashboard.php',
    'crime_data_department' => 'dashboard.php',
    'public_safety_department' => 'public-safety-dashboard.php',
    'health_and_safety_department' => 'health-dashboard.php',
    'disaster_preparedness_department' => 'disaster-dashboard.php',
    'emergency_communication_department' => 'comm-dashboard.php',
];

$dashboardFile = $dashboardFiles[$user->department] ?? 'dashboard.php';

// Build redirect URL
$redirectUrl = "https://{$subdomain}.alertaraqc.com/{$dashboardFile}?token={$token}";

// Return to user
return response()->json([
    'success' => true,
    'redirect_url' => $redirectUrl,
    'token' => $token,
]);
```

> **⚠️ Need to change the redirection mapping?**
>
> **Contact Admin:** PM ME TO CHANGE THE REDIRECTION
>
> **What can be changed:**
> - Department → Subdomain mapping
> - Dashboard file names per department
> - Any routing logic
>
> **Changes are made in:** `AuthController.php` (lines 318-358)

---

## 🔴 Laravel Integration

### Step 1️⃣: Install JWT Package

```bash
composer require tymon/jwt-auth:^2.0
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

### Step 2️⃣: Configure .env

```env
# Database (Already exists in LGU)
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=LGU
DB_USERNAME=your_username
DB_PASSWORD=your_password

# JWT Configuration
JWT_SECRET=(PROVIDED BY ADMIN)
JWT_ALGO=HS256
JWT_TTL=60

# Centralized Login Domain
MAIN_DOMAIN=https://alertaraqc.com
```

### Step 3️⃣: Copy Auth Files

Copy these files from centralized login to your dashboard:

```bash
# Copy to your project
cp examples/auth-include.php your-dashboard/app/Includes/

# Or for Pure PHP
cp examples/auth-include-pure-php.php your-dashboard/public/
```

### Step 4️⃣: Use in Your Dashboard

**File: `resources/views/dashboard.blade.php`**

```php
<?php
// Add at TOP of file (before any HTML output)
require_once app_path('Includes/auth-include.php');
?>

<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <!-- Now user is authenticated and available -->

    <nav>
        <h1>Welcome, <?php echo htmlspecialchars(getUserEmail()); ?></h1>
        <a href="?action=logout" class="btn btn-logout">Logout</a>
    </nav>

    <div class="content">
        <p><strong>Department:</strong> <?php echo getDepartmentName(); ?></p>
        <p><strong>Role:</strong> <?php echo getUserRole(); ?></p>

        <?php if (isAdmin()): ?>
            <div class="admin-panel">
                Admin Panel Content Here
            </div>
        <?php endif; ?>
    </div>

    <!-- Add token refresh script (optional) -->
    <?php echo getTokenRefreshScript(); ?>
</body>
</html>
```

### Step 5️⃣: Protect All Pages

Do **the same for all pages** in your dashboard:

```
public/
├── dashboard/
│   ├── index.php          ← Add auth-include.php at top
│   ├── reports.php        ← Add auth-include.php at top
│   ├── analytics.php      ← Add auth-include.php at top
│   └── settings.php       ← Add auth-include.php at top
```

---

## 🟡 Pure PHP Integration

### Step 1️⃣: Install Composer Packages

```bash
composer require firebase/php-jwt
composer require symfony/dotenv
```

### Step 2️⃣: Setup .env File

**File: `.env` (in project root)**

```env
JWT_SECRET=(PROVIDED BY ADMIN)
MAIN_DOMAIN=https://alertaraqc.com
```

### Step 3️⃣: Copy Auth File

```bash
cp examples/auth-include-pure-php.php your-dashboard/public/
```

### Step 4️⃣: Use in Your Pages

**File: `public/dashboard.php`**

```php
<?php
// Load autoloader
require_once __DIR__ . '/../vendor/autoload.php';

// Add authentication (handles everything)
require_once __DIR__ . '/auth-include-pure-php.php';

// User is now authenticated!
?>

<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <nav>
        <h1>Welcome, <?php echo htmlspecialchars(getUserEmail()); ?></h1>
        <a href="?action=logout" class="btn btn-logout">Logout</a>
    </nav>

    <div class="content">
        <p><strong>Department:</strong> <?php echo getDepartmentName(); ?></p>
        <p><strong>Role:</strong> <?php echo getUserRole(); ?></p>

        <?php if (isAdmin()): ?>
            <div class="admin-panel">
                Admin Panel Content
            </div>
        <?php endif; ?>
    </div>

    <!-- Token refresh script -->
    <?php echo getTokenRefreshScript(); ?>
</body>
</html>
```

### Step 5️⃣: Protect All Pages

Add the same at the top of **every protected page**:

```php
<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/auth-include-pure-php.php';
// Page is now protected ✅
?>
```

---

## 📚 Available Helper Functions

```php
// Get user information
getCurrentUser()           // Returns full user array
getUserEmail()            // Get user email
getUserRole()             // Get role ('admin' or 'super_admin')
getUserDepartment()       // Get department code
getDepartmentName()       // Get department name (formatted)

// Check permissions
isAdmin()                 // Boolean check
isSuperAdmin()            // Boolean check

// Logout
getLogoutUrl()           // Get logout URL
logout()                 // Execute logout (for Pure PHP)

// Token management
getTokenRefreshScript()  // Get JavaScript for token refresh
```

### Usage Examples

```php
<!-- Display user email -->
<?php echo getUserEmail(); ?>

<!-- Check if admin -->
<?php if (isAdmin()): ?>
    <div>Admin Controls</div>
<?php endif; ?>

<!-- Show department -->
<p>Department: <?php echo getDepartmentName(); ?></p>

<!-- Logout link -->
<a href="?action=logout">Logout</a>
```

---

## 🗄️ Database Info

### Database: `LGU`

**Tables already exist**, you only need to:

1. **Insert admin credentials into `centralized_admin_user` table:**

```sql
INSERT INTO centralized_admin_user
(email, password_hash, department, role)
VALUES
('admin@alertaraqc.com', 'hashed_password_here', 'crime_data_department', 'admin');
```

2. **Make sure your database credentials match in `.env`:**

```env
DB_DATABASE=LGU
DB_USERNAME=your_username
DB_PASSWORD=your_password
```

### Table Structure

```sql
CREATE TABLE centralized_admin_user (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    department ENUM('law_enforcement_department', 'traffic_and_transport_department', 'fire_and_rescue_department', 'emergency_response_department', 'community_policing_department', 'crime_data_department', 'public_safety_department', 'health_and_safety_department', 'disaster_preparedness_department', 'emergency_communication_department') NOT NULL,
    role ENUM('admin', 'super_admin') DEFAULT 'admin',
    ip_address VARCHAR(45),
    attempt_count INT DEFAULT 0,
    unlock_token VARCHAR(255),
    unlock_token_expiry DATETIME,
    last_login DATETIME DEFAULT NOW(),
    last_activity DATETIME DEFAULT NOW(),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

---

## 🚀 Testing Your Integration

### Test Checklist

- [ ] User can log in via centralized login
- [ ] Redirected to dashboard with token
- [ ] User information displays correctly
- [ ] Token stored in session
- [ ] Can navigate between pages without losing session
- [ ] Logout redirects to login page
- [ ] Department name displays correctly
- [ ] Admin/super_admin roles work

### Debug Tips

Check browser console:
```javascript
// View stored user data
console.log(localStorage.getItem('user_data'));

// View current token
console.log(sessionStorage.getItem('jwt_token'));
```

Check Laravel logs:
```bash
tail -f storage/logs/laravel.log
```

---

## ⚠️ Common Issues

### Issue: "Token not found in URL or session"

**Solution:** Make sure token is in URL when first visiting dashboard
```
✅ https://crime-analytics.alertaraqc.com/dashboard?token=eyJ0eXAi...
```

### Issue: Department showing empty

**Solution:** Verify JWT_SECRET matches the centralized login server's SECRET

### Issue: Logout not working

**Solution:** Make sure `.env` has correct `MAIN_DOMAIN`
```env
MAIN_DOMAIN=https://alertaraqc.com
```

### Issue: "Call to undefined function"

**Solution:** Make sure you included auth file at TOP of page (before any HTML)

### Issue: Token displays in URL - Is this secure?

**Answer:** ✅ **YES, it's secure!** Here's why:

```
🔒 Security Features:
├─ HTTPS Encryption
│  └─ Token encrypted in transit (TLS/SSL)
│
├─ Initial Redirect Only
│  └─ Token visible only on first page load
│
├─ Session Storage
│  └─ Stored in server session after initial load
│  └─ Subsequent pages don't show token in URL
│
└─ Token Features
   ├─ JWT signed with JWT_SECRET (verified on every request)
   ├─ Short expiration (1 hour default)
   └─ Cannot be tampered with without valid SECRET
```

**Why it appears in URL:**
- Initial redirect needs to transfer token from login server to dashboard
- HTTPS encrypts the entire connection (including URL)
- Token is immediately stored in session
- Browser history shows clean URLs after that

**Best Practice:**
- ✅ Display in URL for initial redirect (HTTPS encrypted)
- ✅ Store in session for all subsequent requests
- ✅ No token visible in browser history after page navigation
- ✅ Session persists even if user bookmarks the page

So don't worry - **all pages can display tokens at the top, it's completely safe with HTTPS** 🔐

---

## 🔒 Security Best Practices

✅ **Do:**
- Keep JWT_SECRET safe (never commit to Git)
- Always use HTTPS in production
- Validate tokens on every request
- Store sensitive data in session, not localStorage
- Use short token expiration times

❌ **Don't:**
- Don't expose JWT_SECRET in code
- Don't use HTTP in production
- Don't ignore token expiration
- Don't store passwords in localStorage
- Don't skip authentication checks

---

## 📞 Getting Help

### Need JWT_SECRET or API Keys?

Contact your administrator and request:
- [ ] JWT_SECRET (for .env)
- [ ] Database credentials (for .env)
- [ ] Centralized login URL (for MAIN_DOMAIN)

### Files You Need

Ask admin to provide:
1. `auth-include.php` (for Laravel)
2. `auth-include-pure-php.php` (for Pure PHP)
3. Centralized login credentials

---

## 📋 Environment Variables Reference

### Laravel (.env) - Complete Configuration

```env
# ============================================
# Application
# ============================================
APP_NAME="AlertaraQC"
APP_ENV=production
APP_DEBUG=false
APP_URL=https://login.alertaraqc.com

# ============================================
# Database (LGU)
# ============================================
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=LGU
DB_USERNAME=(PROVIDED BY ADMIN)
DB_PASSWORD=(PROVIDED BY ADMIN)

# ============================================
# JWT Authentication
# ============================================
JWT_SECRET=(PROVIDED BY ADMIN - Keep this SAFE!)
JWT_ALGO=HS256
JWT_TTL=60

# ============================================
# Centralized Login URLs
# ============================================
MAIN_DOMAIN=https://alertaraqc.com
CENTRALIZED_LOGIN_URL=https://login.alertaraqc.com
API_VALIDATE_ENDPOINT=https://login.alertaraqc.com/api/auth/validate

# ============================================
# Session Configuration (IMPORTANT!)
# ============================================
SESSION_DRIVER=file
SESSION_LIFETIME=120
SESSION_DOMAIN=.alertaraqc.com
SESSION_PATH=/
SESSION_SECURE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax

# ============================================
# Email Configuration
# ============================================
MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=465
MAIL_USERNAME=(PROVIDED BY ADMIN)
MAIL_PASSWORD=(PROVIDED BY ADMIN)
MAIL_FROM_ADDRESS=admin@alertaraqc.com
MAIL_FROM_NAME="AlertaraQC Admin"
```

### Pure PHP (.env) - Minimal Configuration

```env
# ============================================
# JWT
# ============================================
JWT_SECRET=(PROVIDED BY ADMIN - Keep this SAFE!)

# ============================================
# Centralized Login
# ============================================
MAIN_DOMAIN=https://alertaraqc.com
CENTRALIZED_LOGIN_URL=https://login.alertaraqc.com
API_VALIDATE_ENDPOINT=https://login.alertaraqc.com/api/auth/validate

# ============================================
# Session Configuration
# ============================================
SESSION_DOMAIN=.alertaraqc.com
SESSION_LIFETIME=120
SESSION_SECURE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
```

### Department Subdomain (.env for Dashboard Servers)

**For each department subdomain dashboard (e.g., `crime-analytics.alertaraqc.com`):**

```env
# ============================================
# Centralized Login URLs
# ============================================
CENTRALIZED_LOGIN_URL=https://login.alertaraqc.com
API_VALIDATE_ENDPOINT=https://login.alertaraqc.com/api/auth/validate
MAIN_DOMAIN=https://alertaraqc.com

# ============================================
# Session Configuration
# ============================================
SESSION_DOMAIN=.alertaraqc.com
SESSION_LIFETIME=120
SESSION_SECURE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax

# ============================================
# Optional: Database for YOUR dashboard
# ============================================
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=your_dashboard_db
DB_USERNAME=(YOUR CREDENTIALS)
DB_PASSWORD=(YOUR CREDENTIALS)
```

---

## 🌍 Local Development vs Production .env

### Local Development .env

**Use this for localhost development:**

```env
# ============================================
# Application (LOCAL)
# ============================================
APP_NAME="AlertaraQC"
APP_ENV=local
APP_DEBUG=true
APP_URL=http://localhost:8000

# ============================================
# Database (LOCAL - Usually localhost)
# ============================================
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=LGU
DB_USERNAME=root
DB_PASSWORD=

# ============================================
# JWT Authentication
# ============================================
JWT_SECRET=(PROVIDED BY ADMIN)
JWT_ALGO=HS256
JWT_TTL=60

# ============================================
# Centralized Login (IMPORTANT - Use production URLs even in local!)
# ============================================
MAIN_DOMAIN=https://alertaraqc.com
CENTRALIZED_LOGIN_URL=https://login.alertaraqc.com
API_VALIDATE_ENDPOINT=https://login.alertaraqc.com/api/auth/validate

# ============================================
# Session Configuration (LOCAL - LESS STRICT)
# ============================================
SESSION_DRIVER=file
SESSION_LIFETIME=120
SESSION_DOMAIN=localhost
SESSION_PATH=/
SESSION_SECURE=false        # ⚠️ FALSE for local HTTP
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax

# ============================================
# Mail (LOCAL - Use Mailtrap or similar)
# ============================================
MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=465
MAIL_USERNAME=(TEST ACCOUNT)
MAIL_PASSWORD=(TEST ACCOUNT)
MAIL_FROM_ADDRESS=test@alertaraqc.com
MAIL_FROM_NAME="AlertaraQC Test"
```

### Production .env

**Use this for live deployment:**

```env
# ============================================
# Application (PRODUCTION)
# ============================================
APP_NAME="AlertaraQC"
APP_ENV=production
APP_DEBUG=false
APP_URL=https://login.alertaraqc.com

# ============================================
# Database (PRODUCTION - Usually remote server)
# ============================================
DB_CONNECTION=mysql
DB_HOST=your-db-server.com
DB_PORT=3306
DB_DATABASE=LGU
DB_USERNAME=(PROVIDED BY ADMIN - SECURE!)
DB_PASSWORD=(PROVIDED BY ADMIN - SECURE!)

# ============================================
# JWT Authentication
# ============================================
JWT_SECRET=(PROVIDED BY ADMIN - KEEP SAFE!)
JWT_ALGO=HS256
JWT_TTL=60

# ============================================
# Centralized Login (Production URLs)
# ============================================
MAIN_DOMAIN=https://alertaraqc.com
CENTRALIZED_LOGIN_URL=https://login.alertaraqc.com
API_VALIDATE_ENDPOINT=https://login.alertaraqc.com/api/auth/validate

# ============================================
# Session Configuration (PRODUCTION - STRICT!)
# ============================================
SESSION_DRIVER=file
SESSION_LIFETIME=120
SESSION_DOMAIN=.alertaraqc.com      # Dot prefix for all subdomains
SESSION_PATH=/
SESSION_SECURE=true                 # ✅ TRUE for HTTPS only
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax

# ============================================
# Mail (PRODUCTION - Real SMTP)
# ============================================
MAIL_MAILER=smtp
MAIL_HOST=smtp.gmail.com            # Or your email provider
MAIL_PORT=465
MAIL_USERNAME=(YOUR ADMIN EMAIL)
MAIL_PASSWORD=(YOUR APP PASSWORD)
MAIL_FROM_ADDRESS=admin@alertaraqc.com
MAIL_FROM_NAME="AlertaraQC Admin"
```

### Key Differences Between Local and Production

| Setting | Local | Production | Why? |
|---------|-------|-----------|------|
| `APP_ENV` | `local` | `production` | Controls error reporting and logging |
| `APP_DEBUG` | `true` | `false` | Don't expose errors in production |
| `APP_URL` | `http://localhost:8000` | `https://login.alertaraqc.com` | Used for redirect URLs |
| `SESSION_DOMAIN` | `localhost` | `.alertaraqc.com` | Local doesn't need subdomain sharing |
| `SESSION_SECURE` | `false` | `true` | HTTP in local, HTTPS in production |
| `DB_HOST` | `127.0.0.1` | `your-db-server.com` | Remote database in production |
| `MAIL_HOST` | `smtp.mailtrap.io` (test) | `smtp.gmail.com` (real) | Test emails locally, real emails in prod |

### ⚠️ CRITICAL: Local Development Settings

When developing locally, **use these settings** to avoid session/cookie issues:

```env
# For local development on http://localhost:8000
SESSION_DOMAIN=localhost          # NOT .localhost!
SESSION_SECURE=false              # HTTP not HTTPS
SESSION_PATH=/
APP_URL=http://localhost:8000
```

### ⚠️ CRITICAL: Production Settings

When deploying to production, **use these settings** for security:

```env
# For production on https://login.alertaraqc.com
SESSION_DOMAIN=.alertaraqc.com    # Include the dot!
SESSION_SECURE=true               # HTTPS only
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
APP_URL=https://login.alertaraqc.com
APP_DEBUG=false
```

### How to Manage Multiple .env Files

**Option 1: Use .env and .env.production (Recommended)**

```bash
# Development
.env                    # Used by `php artisan` commands

# Production
.env.production         # Used only when deployed
```

**Option 2: Use git-ignored .env files**

```bash
# .gitignore
.env
.env.local
.env.production
```

**Option 3: Use environment variables in hosting panel**

Most hosting panels (cPanel, Plesk, etc.) allow you to set environment variables directly without .env files.

### Deploying to Production

**Step 1: Create production .env**
```bash
cp .env .env.production
# Edit .env.production with production values
```

**Step 2: Upload to server (but NOT to Git)**
```bash
# Add to .gitignore
echo ".env.production" >> .gitignore
```

**Step 3: Set on server during deployment**
```bash
# On server, create .env with production values
# Or set environment variables in hosting control panel
```

**Step 4: Verify settings**
```bash
php artisan config:show | grep SESSION
php artisan config:show | grep APP_DEBUG
```

### Environment Variables Explained

| Variable | Description | Example |
|----------|-------------|---------|
| `JWT_SECRET` | Secret key for signing JWTs - **KEEP SAFE!** | `your-super-secret-key-here` |
| `MAIN_DOMAIN` | Main login domain | `https://alertaraqc.com` |
| `CENTRALIZED_LOGIN_URL` | Centralized login server URL | `https://login.alertaraqc.com` |
| `API_VALIDATE_ENDPOINT` | API endpoint to validate tokens | `https://login.alertaraqc.com/api/auth/validate` |
| `SESSION_DOMAIN` | Allows sharing sessions across subdomains | `.alertaraqc.com` (dot prefix!) |
| `SESSION_SECURE` | Only send session cookie over HTTPS | `true` (production), `false` (local dev) |
| `SESSION_HTTP_ONLY` | Prevent JavaScript access to session | `true` |
| `SESSION_SAME_SITE` | SameSite cookie attribute | `lax` (recommended) |

### How to Set Up .env Files

**Step 1:** Request credentials from admin
```bash
# Ask admin for:
# - JWT_SECRET
# - Database credentials (if using database)
# - Confirmation of MAIN_DOMAIN
```

**Step 2:** Create `.env` file in project root
```bash
cp .env.example .env
```

**Step 3:** Update values
```bash
nano .env  # or use your favorite editor
```

**Step 4:** Generate Laravel application key (Laravel only)
```bash
php artisan key:generate
```

**Step 5:** For production, add to `.gitignore`
```bash
echo ".env" >> .gitignore
```

### ⚠️ Important: Never Commit .env

**NEVER commit `.env` to Git!** It contains sensitive information:
- JWT_SECRET
- Database passwords
- API keys

**Always:**
- ✅ Add `.env` to `.gitignore`
- ✅ Use `.env.example` for reference
- ✅ Share credentials securely via admin
- ✅ Use environment-specific .env files (`.env.local`, `.env.production`)

---

## 📚 Full API Reference

### User Functions

```php
getCurrentUser()
// Returns: ['id' => 1, 'email' => 'user@..', 'department' => '...', ...]

getUserEmail()
// Returns: 'user@example.com'

getUserRole()
// Returns: 'admin' or 'super_admin'

getUserDepartment()
// Returns: 'crime_data_department'

getDepartmentName()
// Returns: 'Crime Data Analytics Department'

getUserId()
// Returns: User ID
```

### Permission Functions

```php
isAdmin()
// Returns: true/false

isSuperAdmin()
// Returns: true/false
```

### Utility Functions

```php
getLogoutUrl()
// Returns: 'https://login.alertaraqc.com'

getTokenRefreshScript()
// Returns: JavaScript code for token refresh
```

---

## 🎯 Next Steps

1. ✅ Request credentials from admin
2. ✅ Update .env with JWT_SECRET and database info
3. ✅ Copy auth-include file
4. ✅ Add to your dashboard pages
5. ✅ Test login flow
6. ✅ Deploy to production

---

## 📞 Support

### General Questions
- **Email:** admin@alertaraqc.com
- **Documentation:** See `IMPLEMENTATION_GUIDE.md`

### Special Requests

#### 🔄 Need to Change Subdomain Redirection?

If you need to change which subdomain a department redirects to:

- **Contact:** PM ME TO CHANGE THE REDIRECTION
- **Configuration File:** `AuthController.php` in centralized login (lines 318-358)
- **What can be changed:**
  - Department → Subdomain mapping
  - Dashboard file names
  - Redirect URLs
  - Any department-based routing logic

**Current Mapping:**
```php
$departmentSubdomains = [
    'law_enforcement_department' => 'law-enforcement.alertaraqc.com',
    'traffic_and_transport_department' => 'traffic.alertaraqc.com',
    'fire_and_rescue_department' => 'fire.alertaraqc.com',
    'emergency_response_department' => 'emergency.alertaraqc.com',
    'community_policing_department' => 'community.alertaraqc.com',
    'crime_data_department' => 'crime-analytics.alertaraqc.com',
    'public_safety_department' => 'public-safety.alertaraqc.com',
    'health_and_safety_department' => 'health-safety.alertaraqc.com',
    'disaster_preparedness_department' => 'disaster.alertaraqc.com',
    'emergency_communication_department' => 'emergency-comm.alertaraqc.com'
];

$dashboardFiles = [
    'law_enforcement_department' => 'law-dashboard.php',
    'traffic_and_transport_department' => 'traffic-dashboard.php',
    'fire_and_rescue_department' => 'fire-dashboard.php',
    'emergency_response_department' => 'emergency-dashboard.php',
    'community_policing_department' => 'community-dashboard.php',
    'crime_data_department' => 'dashboard.php',
    'public_safety_department' => 'public-safety-dashboard.php',
    'health_and_safety_department' => 'health-dashboard.php',
    'disaster_preparedness_department' => 'disaster-dashboard.php',
    'emergency_communication_department' => 'comm-dashboard.php'
];
```

**To Request a Change:**
1. Tell admin which department you want to change
2. Provide the new subdomain name (or dashboard file)
3. Admin will update `AuthController.php`
4. Changes take effect immediately

**Example Change Request:**
```
"Can you change crime_data_department to redirect to
crime.alertaraqc.com instead of crime-analytics.alertaraqc.com?"
```

#### 🔐 Need JWT_SECRET or Credentials?
- **Contact:** Admin
- **What you'll receive:**
  - JWT_SECRET (for .env)
  - Database credentials (for .env)
  - Centralized login URL (MAIN_DOMAIN)

---

**Last Updated:** 2026-02-15
**Version:** 2.1.0 (Local/Production .env Configurations Added)
**Status:** ✅ Production Ready

---

## 📝 Changelog

### Version 2.1.0 (2026-02-15)
- 🌍 Added Local Development vs Production .env guide
- 📋 Complete .env examples for local and production
- ⚠️ Critical settings guide for security
- 📊 Comparison table for local vs production settings
- 🚀 Deployment checklist and procedures

### Version 2.0.0 (2026-02-15)
- ✨ Added API Endpoint section (recommended approach)
- 📚 Updated environment variables documentation
- 🔐 Enhanced security configuration guide
- 🎯 Added quick start examples for API endpoint
- ✅ Added comparison table (Include File vs API Endpoint)

### Version 1.0.0 (2026-02-14)
- Initial release
- Include file-based authentication
- Complete integration guide
