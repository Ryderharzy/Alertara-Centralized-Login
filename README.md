# 🔐 Centralized Login Integration Guide

> How to integrate **AlerTara Centralized Login System** into your dashboard using JWT authentication

---

## 📋 Quick Start Guide

| Framework | Tutorial |
|-----------|----------|
| **🟡 Pure PHP** | [See Simple Example Below](#simple-example-pure-php) |
| **🔴 Laravel** | [See Simple Example Below](#simple-example-laravel) |

---

## ⚡ The API Endpoint (All You Need)

**One Simple API Endpoint:**
```
https://login.alertaraqc.com/api/auth/validate?token=YOUR_JWT_TOKEN
```

**That's it!** No files to copy. Just call this endpoint and you get:
- User email
- User role
- Department name
- Everything you need

---

## 🟡 Pure PHP - Step by Step

### Step 1: Create `dashboard.php`

```php
<?php
session_start();

// Step 1: Get JWT token from URL or session
$token = $_GET['token'] ?? $_SESSION['jwt_token'] ?? null;

if (!$token) {
    header('Location: https://login.alertaraqc.com');
    exit;
}

// Store in session for next page visit
$_SESSION['jwt_token'] = $token;

// Step 2: Validate token via API
$ch = curl_init('https://login.alertaraqc.com/api/auth/validate');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Bearer ' . $token,
]);

$response = json_decode(curl_exec($ch), true);
curl_close($ch);

// Step 3: Check if validation passed
if (!$response['authenticated']) {
    header('Location: https://login.alertaraqc.com');
    exit;
}

// Step 4: Get user data from response
$user = $response['user'];
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

    <h1>Welcome <?= $user['email'] ?></h1>
    <p>Role: <strong><?= $user['role'] ?></strong></p>
    <p>Department: <strong><?= $user['department_name'] ?></strong></p>
    <a href="https://login.alertaraqc.com/logout">Logout</a>
</body>
</html>
```

### Step 2: That's it!

Your dashboard now validates tokens automatically when users arrive from the login system.

---

## 🔴 Laravel - Step by Step

### Step 1: Create a Route in `routes/web.php`

```php
use Illuminate\Support\Facades\Http;

Route::get('/dashboard', function () {
    // Get token from URL or session
    $token = request('token') ?? session('jwt_token');

    if (!$token) {
        return redirect('https://login.alertaraqc.com');
    }

    // Save token in session
    session(['jwt_token' => $token]);

    // Call API to validate token
    $response = Http::withToken($token)
        ->get('https://login.alertaraqc.com/api/auth/validate');

    // If not authenticated, redirect to login
    if (!$response['authenticated']) {
        return redirect('https://login.alertaraqc.com');
    }

    // Pass user data to view
    return view('dashboard', ['user' => $response['user']]);
});
```

### Step 2: Create a View in `resources/views/dashboard.blade.php`

```blade
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

    <h1>Welcome {{ $user['email'] }}</h1>
    <p>Role: <strong>{{ $user['role'] }}</strong></p>
    <p>Department: <strong>{{ $user['department_name'] }}</strong></p>
    <a href="https://login.alertaraqc.com/logout">Logout</a>
</body>
</html>
```

### Step 3: That's it!

Your Laravel dashboard now validates tokens automatically.

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

**Solution:** Make sure you're calling the API endpoint correctly. Check the response from `/api/auth/validate` contains the required `user` object.

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

### Common Questions

**Q: Do I need to set up JWT_SECRET on my dashboard?**
A: No! Only the centralized login server needs JWT_SECRET. Your dashboard just validates tokens via the API endpoint.

**Q: Do I need database for my dashboard?**
A: No! The centralized login server has the database. Your dashboard just calls the API.


## ⚙️ Essential .env Configuration

You only need these values. Nothing more!

### For Laravel Dashboard

```env
APP_ENV=production
APP_DEBUG=false
APP_URL=https://crime-analytics.alertaraqc.com
```

### For Pure PHP Dashboard

No .env file needed! Just hardcode the login URL in your code:

```php
// In your PHP files
$loginUrl = 'https://login.alertaraqc.com';
$apiEndpoint = 'https://login.alertaraqc.com/api/auth/validate';
```

That's all you need! The token is passed automatically in the URL when user logs in.

---

## 📚 API Response Reference

### Response Format

When you call the API endpoint, you get this response:

```json
{
  "authenticated": true,
  "user": {
    "id": 1,
    "email": "admin@alertaraqc.com",
    "role": "admin",
    "department": "crime_data_department",
    "department_name": "Crime Data Analytics Department",
    "exp": 1645000000
  }
}
```

### User Fields

| Field | Type | Example | Description |
|-------|------|---------|-------------|
| `id` | integer | `1` | User ID in database |
| `email` | string | `admin@alertaraqc.com` | User email address |
| `role` | string | `admin` or `super_admin` | User role |
| `department` | string | `crime_data_department` | Department code |
| `department_name` | string | `Crime Data Analytics Department` | Human-readable department name |
| `exp` | integer | `1645000000` | Token expiration (Unix timestamp) |

### Using User Data in Your Code

**Pure PHP:**
```php
$user = $response['user'];
echo $user['email'];              // 'admin@alertaraqc.com'
echo $user['role'];               // 'admin'
echo $user['department_name'];    // 'Crime Data Analytics Department'
```

**Laravel Blade:**
```blade
{{ $user['email'] }}
{{ $user['role'] }}
{{ $user['department_name'] }}
```

**JavaScript:**
```javascript
const userData = <?= json_encode($user) ?>;
console.log(userData.email);
console.log(userData.role);
```

---

## 🎯 Next Steps

1. ✅ Copy the Pure PHP or Laravel code above to your dashboard
2. ✅ Test it by logging in from https://login.alertaraqc.com
3. ✅ Verify user data displays correctly
4. ✅ Deploy to production

That's it!

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

---

**Last Updated:** 2026-02-15
**Version:** 3.0.0 (Simplified API Endpoint Approach)
**Status:** ✅ Production Ready

---

## 📝 Changelog

### Version 3.0.0 (2026-02-15) - Simplified!
- 🎯 Removed all auth-include file references
- 📝 Step-by-step examples for Pure PHP and Laravel
- ⚙️ Simplified .env configuration (only essential values)
- ❓ Updated FAQ to clarify dashboard vs centralized login setup
- 🚀 Made documentation easy to understand (not confusing)

### Version 2.1.0 (2026-02-15)
- 🌍 Added Local Development vs Production .env guide
- 📋 Complete .env examples for local and production
- ⚠️ Critical settings guide for security

### Version 2.0.0 (2026-02-15)
- ✨ Added API Endpoint section (recommended approach)
- 📚 Updated environment variables documentation

### Version 1.0.0 (2026-02-14)
- Initial release with include file approach
