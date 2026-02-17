<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use App\Models\CentralizedAdminUser;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function showLogin()
    {
        return view('index');
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
            'cf-turnstile-response' => 'required'
        ]);

        if ($validator->fails()) {
            if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                return response()->json(['errors' => $validator->errors()], 422);
            }
            return redirect()->back()
                ->withErrors($validator)
                ->withInput($request->except('password'));
        }

        // Verify Cloudflare Turnstile
        $response = file_get_contents('https://challenges.cloudflare.com/turnstile/v0/siteverify', false, stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/x-www-form-urlencoded',
                'content' => http_build_query([
                    'secret' => config('services.turnstile.secret_key'),
                    'response' => $request->input('cf-turnstile-response'),
                    'remoteip' => $request->ip()
                ])
            ]
        ]));

        $result = json_decode($response);
        if (!$result->success) {
            if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                return response()->json(['message' => 'CAPTCHA verification failed.'], 400);
            }
            return redirect()->back()
                ->withErrors(['cf-turnstile-response' => 'CAPTCHA verification failed.'])
                ->withInput($request->except('password'));
        }

        $user = CentralizedAdminUser::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password_hash)) {
            // Use Redis cache for attempt count tracking
            $accountLocked = false;
            if ($user) {
                $cacheKey = 'login_attempts_' . $user->id;
                $attemptCount = cache()->get($cacheKey, 0) + 1;

                // Store attempt count in Redis for 1 hour
                cache()->put($cacheKey, $attemptCount, now()->addHour());

                // Lock account after 3 failed attempts
                if ($attemptCount >= 3) {
                    $unlockToken = Str::random(60);
                    $unlockCacheKey = 'account_locked_' . $user->id;

                    // Store unlock token in Redis for 1 hour (unique per user)
                    cache()->put($unlockCacheKey, $unlockToken, now()->addHour());
                    Log::info('Account locked, unlock token stored in Redis for user: ' . $user->id);

                    // Send unlock email with unlock link
                    try {
                        Mail::send('emails.account-locked', [
                            'user' => $user,
                            'unlockToken' => $unlockToken,
                            'ipAddress' => $request->ip()
                        ], function ($message) use ($user) {
                            $message->to($user->email)
                                ->subject('Account Locked - Security Alert');
                        });
                        Log::info('Account locked email sent to: ' . $user->email);
                        $accountLocked = true;
                    } catch (\Exception $e) {
                        // Log email error but don't fail the request
                        Log::error('Failed to send account locked email: ' . $e->getMessage());
                        $accountLocked = true;
                    }
                }
            }

            // Show different message if account is locked
            if ($accountLocked) {
                if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                    return response()->json([
                        'message' => 'Your account has been locked due to multiple failed login attempts. We have sent an unlock link to your email address. Please check your inbox.'
                    ], 403);
                }
                return redirect()->back()
                    ->withErrors(['email' => 'Your account has been locked due to multiple failed login attempts. We have sent an unlock link to your email address. Please check your inbox.'])
                    ->withInput($request->except('password'));
            }

            // Regular invalid credentials message
            if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                return response()->json(['message' => 'Invalid email or password'], 401);
            }
            return redirect()->back()
                ->withErrors(['email' => 'Invalid email or password'])
                ->withInput($request->except('password'));
        }

        // Check if account is locked (Redis cache only)
        $cacheKey = 'account_locked_' . $user->id;
        $isLockedInCache = cache()->has($cacheKey);

        if ($isLockedInCache) {
            if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                return response()->json(['message' => 'Account is temporarily locked. Please check your email for unlock instructions.'], 403);
            }
            return redirect()->back()
                ->withErrors(['email' => 'Account is temporarily locked. Please check your email for unlock instructions.'])
                ->withInput($request->except('password'));
        }

        // Reset attempt count on successful login (Redis only)
        $attemptCacheKey = 'login_attempts_' . $user->id;
        $lockCacheKey = 'account_locked_' . $user->id;
        cache()->forget($attemptCacheKey);
        cache()->forget($lockCacheKey);
        Log::info('Login attempts and lock cleared from Redis for user: ' . $user->id);

        // Update only login metadata in database
        $user->update([
            'last_login' => now('Asia/Manila'),
            'last_activity' => now('Asia/Manila'),
            'ip_address' => $request->ip()
        ]);

        // Generate OTP for mandatory 2FA
        $otpCode = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        // Store OTP in Redis (unique per user)
        try {
            $otpCacheKey = 'otp_' . $user->id;

            // Store OTP in Redis for 5 minutes
            cache()->put($otpCacheKey, $otpCode, now()->addMinutes(5));
            Log::info('OTP generated and stored in Redis for user: ' . $user->id);

            // Send OTP via email
            try {
                Mail::send('emails.otp-verification', [
                    'user' => $user,
                    'otpCode' => $otpCode,
                    'ipAddress' => $request->ip()
                ], function ($message) use ($user) {
                    $message->to($user->email)
                        ->subject('Your OTP Verification Code');
                });
                Log::info('OTP sent successfully to: ' . $user->email);
            } catch (\Exception $e) {
                Log::error('Failed to send OTP email: ' . $e->getMessage());
                // Continue anyway - user can still enter OTP manually
            }

            // Set session
            session(['otp_admin_id' => $user->id]);

            if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                return response()->json(['success' => true], 200);
            }

            return redirect()->route('otp.verify');
        } catch (\Exception $e) {
            Log::error('Error during OTP generation: ' . $e->getMessage());
            if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                return response()->json(['message' => 'An error occurred. Please try again.'], 500);
            }
            return redirect()->back()->withErrors(['email' => 'An error occurred. Please try again.']);
        }
    }

    public function resendOTP(Request $request)
    {
        $adminId = session('otp_admin_id');

        if (!$adminId) {
            return response()->json([
                'success' => false,
                'error' => 'Session expired. Please login again.'
            ], 401);
        }

        try {
            // Get user data
            $user = CentralizedAdminUser::find($adminId);
            if (!$user) {
                return response()->json([
                    'success' => false,
                    'error' => 'User not found.'
                ], 404);
            }

            // Generate new OTP
            $otpCode = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

            // Store new OTP in Redis (unique per user, replaces old OTP)
            $otpCacheKey = 'otp_' . $adminId;
            cache()->put($otpCacheKey, $otpCode, now()->addMinutes(5));
            Log::info('New OTP generated and stored in Redis for user: ' . $adminId);

            // Send OTP via email
            try {
                Mail::send('emails.otp-verification', [
                    'user' => $user,
                    'otpCode' => $otpCode,
                    'ipAddress' => $request->ip()
                ], function ($message) use ($user) {
                    $message->to($user->email)
                        ->subject('Your New OTP Verification Code');
                });
                Log::info('New OTP sent successfully to: ' . $user->email);
            } catch (\Exception $e) {
                Log::error('Failed to send new OTP email: ' . $e->getMessage());
                // Continue anyway - user can still enter OTP manually
            }

            return response()->json([
                'success' => true,
                'message' => 'New OTP sent successfully'
            ]);
        } catch (\Exception $e) {
            Log::error('Error during OTP resend: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'error' => 'An error occurred. Please try again.'
            ], 500);
        }
    }

    public function verifyOTP(Request $request)
    {
        $adminId = session('otp_admin_id');
        
        if (!$adminId) {
            return redirect()->route('login.show');
        }

        return view('auth.verify-otp');
    }

    public function submitOTP(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'otp' => 'required|digits:6'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'OTP must be 6 digits'
            ], 422);
        }

        $adminId = session('otp_admin_id');

        if (!$adminId) {
            return response()->json([
                'success' => false,
                'message' => 'Session expired. Please login again.'
            ], 401);
        }

        // Get OTP from Redis cache (unique per user)
        $otpCacheKey = 'otp_' . $adminId;
        $storedOtp = cache()->get($otpCacheKey);

        if (!$storedOtp || $request->otp !== $storedOtp) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid or expired OTP'
            ], 401);
        }

        // OTP verified, get user data
        $user = CentralizedAdminUser::find($adminId);

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User not found'
            ], 404);
        }

        // Generate JWT token using JWTAuth
        $token = \Tymon\JWTAuth\Facades\JWTAuth::fromUser($user);

        // Clean up OTP from Redis immediately after use
        cache()->forget($otpCacheKey);
        Log::info('OTP verified and removed from cache for user: ' . $adminId);

        // Reset login attempts counter after successful OTP verification
        $attemptCacheKey = 'login_attempts_' . $adminId;
        cache()->forget($attemptCacheKey);
        Log::info('Login attempts reset to 0 for user: ' . $adminId);

        session()->forget('otp_admin_id');

        // Define department subdomains
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

        $subdomain = $departmentSubdomains[$user->department] ?? 'default.alertaraqc.com';

        // Role-based access control
        if ($user->role === 'super_admin') {
            // Super admin must have all_departments
            if ($user->department !== 'all_departments') {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid configuration. Super admin must have all_departments.'
                ], 403);
            }
            $redirectUrl = "https://super-admin.alertaraqc.com/dashboard?token={$token}";
        } else if ($user->role === 'admin') {
            // Admin gets department-specific subdomain
            // Option 1: Same filename for all departments
            // $redirectUrl = "https://{$subdomain}/dashboard.php?token={$token}";

            // Option 2: Different filename per department
            $dashboardFiles = [
                'law_enforcement_department' => 'law-dashboard.php',
                'traffic_and_transport_department' => 'traffic-dashboard.php',
                'fire_and_rescue_department' => 'fire-dashboard.php',
                'emergency_response_department' => 'emergency-dashboard.php',
                'community_policing_department' => 'community-dashboard.php',
                'crime_data_department' => 'dashboard',
                'public_safety_department' => 'public-safety-dashboard.php',
                'health_and_safety_department' => 'health-dashboard.php',
                'disaster_preparedness_department' => 'disaster-dashboard.php',
                'emergency_communication_department' => 'comm-dashboard.php'
            ];

            $dashboardFile = $dashboardFiles[$user->department] ?? 'dashboard.php';
            // Include token in URL for initial redirect (HTTPS - secure)
            // auth-include.php will store it in session for subsequent requests
            $redirectUrl = "https://{$subdomain}/{$dashboardFile}?token={$token}";
        } else {
            // Unauthorized role
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized role. Access denied.'
            ], 403);
        }

        return response()->json([
            'success' => true,
            'message' => 'OTP verified successfully',
            'admin' => [
                'id' => $user->id,
                'email' => $user->email,
                'department' => $user->department,
                'role' => $user->role,
                'last_login' => $user->last_login
            ],
            'token' => $token,
            'redirect_url' => $redirectUrl,
            'subdomain' => $subdomain
        ]);
    }

    public function unlockAccount($token)
    {
        // Get email from request query parameter (if provided)
        $email = request('email');
        $user = null;

        // If email provided, find user by email
        if ($email) {
            $user = CentralizedAdminUser::where('email', $email)->first();
        } else {
            // If no email, search through all users to find matching unlock token
            // This is less efficient but works if email is not in URL
            $allUsers = CentralizedAdminUser::all();
            foreach ($allUsers as $u) {
                $lockCacheKey = 'account_locked_' . $u->id;
                $storedToken = cache()->get($lockCacheKey);
                if ($storedToken && $storedToken === $token) {
                    $user = $u;
                    break;
                }
            }
        }

        if (!$user) {
            return redirect('/')->withErrors(['email' => 'Invalid or expired unlock link.']);
        }

        // Verify unlock token from Redis cache
        $lockCacheKey = 'account_locked_' . $user->id;
        $storedToken = cache()->get($lockCacheKey);

        if (!$storedToken || $storedToken !== $token) {
            return redirect('/')->withErrors(['email' => 'Invalid or expired unlock link.']);
        }

        // Clear all Redis cache entries for this user
        $attemptCacheKey = 'login_attempts_' . $user->id;
        cache()->forget($attemptCacheKey);
        cache()->forget($lockCacheKey);

        // Reset attempt count to 0 in Redis
        cache()->put($attemptCacheKey, 0, now()->addHour());

        Log::info('Account unlocked', [
            'user_id' => $user->id,
            'email' => $user->email
        ]);

        return redirect('/')->with('success', 'Your account has been unlocked successfully. You can now login.');
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        // Redirect to login page
        $response = redirect('/login');

        // Get session configuration
        $sessionCookieName = config('session.cookie');
        $sessionDomain = config('session.domain');

        // Clear session cookie from multiple domains to handle both local and production
        // Use -1 to set expiration to past (guarantees deletion)
        $response->cookie($sessionCookieName, '', -1, '/', null, false, true);
        $response->cookie($sessionCookieName, '', -1, '/', 'localhost', false, true);
        $response->cookie($sessionCookieName, '', -1, '/', '.alertaraqc.com', false, true);

        if ($sessionDomain) {
            $response->cookie($sessionCookieName, '', -1, '/', $sessionDomain, false, true);
        }

        // Also clear XSRF/CSRF token
        $response->cookie('XSRF-TOKEN', '', -1, '/', null, false, true);
        $response->cookie('XSRF-TOKEN', '', -1, '/', 'localhost', false, true);
        $response->cookie('XSRF-TOKEN', '', -1, '/', '.alertaraqc.com', false, true);

        return $response;
    }

    /**
     * API Logout endpoint for subdomains
     *
     * POST /api/logout
     * Headers: Authorization: Bearer JWT_TOKEN
     *
     * Returns:
     * { "success": true, "message": "Logged out successfully", "clear_cookies": true }
     */
    public function apiLogout(Request $request)
    {
        try {
            // Get token from Authorization header
            $token = $request->bearerToken() ?? $request->input('token');

            if (!$token) {
                return response()->json([
                    'success' => false,
                    'message' => 'No token provided'
                ], 401);
            }

            try {
                // Decode and validate JWT token
                $authUser = \Tymon\JWTAuth\Facades\JWTAuth::setToken($token)->authenticate();

                if (!$authUser) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Invalid token'
                    ], 401);
                }

                // Store logout time in cache (key: user_logout_ID, value: current timestamp)
                // This will be checked by validateAuth endpoint to reject tokens issued before logout
                cache()->put('user_logout_' . $authUser->id, time(), now()->addDays(7));

                // Log the logout action
                Log::info('User logged out', [
                    'user_id' => $authUser->id,
                    'email' => $authUser->email,
                    'ip' => $request->ip()
                ]);

                // Build response with cookie clearing instructions
                $response = response()->json([
                    'success' => true,
                    'message' => 'Logged out successfully',
                    'clear_cookies' => true
                ], 200);

                // Clear session cookies from ALL domains and paths
                $sessionCookieName = config('session.cookie');
                $cookiesToClear = [
                    'laravel_session',
                    $sessionCookieName,
                    'XSRF-TOKEN',
                    'jwt_token',
                    'remember_me',
                    'auth_token'
                ];

                $domainsToTarget = [
                    '.alertaraqc.com',
                    'login.alertaraqc.com',
                    'localhost',
                    '127.0.0.1'
                ];

                $pathsToTarget = ['/', ''];

                foreach ($cookiesToClear as $cookieName) {
                    foreach ($domainsToTarget as $domain) {
                        foreach ($pathsToTarget as $path) {
                            $response->cookie($cookieName, '', -1, $path ?: '/', $domain, false, true);
                        }
                    }
                }

                return $response;

            } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token has expired'
                ], 401);
            } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token is invalid'
                ], 401);
            }

        } catch (\Exception $e) {
            Log::error('Logout error: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'message' => 'An error occurred during logout'
            ], 500);
        }
    }

    /**
     * API Endpoint to validate JWT token and return user data
     *
     * Usage:
     * GET /api/auth/validate?token=YOUR_JWT_TOKEN
     *
     * Headers:
     * Authorization: Bearer YOUR_JWT_TOKEN
     *
     * Returns:
     * {
     *   "authenticated": true,
     *   "user": {
     *     "id": 1,
     *     "email": "admin@example.com",
     *     "department": "law_enforcement_department",
     *     "department_name": "Law Enforcement Department",
     *     "role": "super_admin",
     *     "exp": 1705123456
     *   }
     * }
     */
    public function validateAuth(Request $request)
    {
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
            'all_departments' => 'All Departments'
        ];

        // Get token from multiple sources
        $token = $request->query('token')
            ?? $request->bearerToken()
            ?? $request->header('X-Access-Token')
            ?? session('jwt_token');

        if (!$token) {
            return response()->json([
                'authenticated' => false,
                'message' => 'No token provided'
            ], 401);
        }

        try {
            // Validate JWT token
            $authUser = \Tymon\JWTAuth\Facades\JWTAuth::setToken($token)->authenticate();

            if (!$authUser) {
                return response()->json([
                    'authenticated' => false,
                    'message' => 'Invalid token'
                ], 401);
            }

            // Get JWT payload with custom claims
            $payload = \Tymon\JWTAuth\Facades\JWTAuth::setToken($token)->getPayload();

            $department = $payload->get('department') ?? '';
            $departmentName = $departmentNames[$department] ?? ucfirst(str_replace('_', ' ', $department));

            // Check token expiration
            $exp = $payload->get('exp');
            if ($exp && $exp < time()) {
                return response()->json([
                    'authenticated' => false,
                    'message' => 'Token expired'
                ], 401);
            }

            // Check if token was issued before logout
            $lastLogoutTime = cache()->get('user_logout_' . $authUser->id, null);
            if ($lastLogoutTime && ($payload->get('iat') ?? 0) < $lastLogoutTime) {
                return response()->json([
                    'authenticated' => false,
                    'message' => 'Token revoked after logout'
                ], 401);
            }

            return response()->json([
                'authenticated' => true,
                'user' => [
                    'id' => $authUser->id,
                    'email' => $payload->get('email') ?? $authUser->email,
                    'department' => $department,
                    'department_name' => $departmentName,
                    'role' => $payload->get('role') ?? 'admin',
                    'exp' => $exp
                ]
            ], 200)->header('Access-Control-Allow-Origin', '*');

        } catch (\Exception $e) {
            Log::error('JWT Validation Error: ' . $e->getMessage(), [
                'token_preview' => substr($token, 0, 50) . '...'
            ]);

            return response()->json([
                'authenticated' => false,
                'message' => 'Token validation failed'
            ], 401);
        }
    }
}
