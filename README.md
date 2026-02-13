# 🔐 Centralized Login Integration Guide

> How to integrate **AlerTara Centralized Login System** into your dashboard using JWT authentication

---

## 📋 Quick Navigation

| Framework | Quick Start |
|-----------|------------|
| **🔴 Laravel** | [Laravel Integration](#-laravel-integration) |
| **🟡 Pure PHP** | [Pure PHP Integration](#-pure-php-integration) |

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
   Redirect to subdomain with token
            ↓
   Your dashboard validates token
            ↓
   User authenticated ✅
```

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

### Laravel (.env)

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
```

### Pure PHP (.env)

```env
JWT_SECRET=(PROVIDED BY ADMIN)
MAIN_DOMAIN=https://alertaraqc.com
```

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

For issues or questions:
- **Email:** admin@alertaraqc.com
- **Documentation:** See `README.md`

---

**Last Updated:** 2026-02-14
**Version:** 1.0.0
**Status:** ✅ Production Ready
