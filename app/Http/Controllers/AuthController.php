<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
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
            // Increment attempt count on failed login
            if ($user) {
                $user->increment('attempt_count');

                // Lock account after 3 failed attempts
                if ($user->attempt_count >= 3) {
                    $unlockToken = Str::random(60);
                    $user->update([
                        'unlock_token' => $unlockToken,
                        'unlock_token_expiry' => now()->addHour()
                    ]);

                    // Send unlock email
                    try {
                        Mail::send('emails.account-locked', [
                            'user' => $user,
                            'unlockToken' => $unlockToken,
                            'ipAddress' => $request->ip()
                        ], function ($message) use ($user) {
                            $message->to($user->email)
                                ->subject('Account Locked - Security Alert');
                        });
                    } catch (\Exception $e) {
                        // Log email error but don't fail the request
                        \Log::error('Failed to send account locked email: ' . $e->getMessage());
                    }
                }
            }

            if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                return response()->json(['message' => 'Invalid credentials'], 401);
            }
            return redirect()->back()
                ->withErrors(['email' => 'Invalid credentials'])
                ->withInput($request->except('password'));
        }

        // Check if account is locked
        if ($user->attempt_count >= 3 && $user->unlock_token_expiry && now()->lt($user->unlock_token_expiry)) {
            if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                return response()->json(['message' => 'Account is temporarily locked. Please check your email for unlock instructions.'], 403);
            }
            return redirect()->back()
                ->withErrors(['email' => 'Account is temporarily locked. Please check your email for unlock instructions.'])
                ->withInput($request->except('password'));
        }

        // Reset attempt count on successful login
        $user->update([
            'attempt_count' => 0,
            'unlock_token' => null,
            'unlock_token_expiry' => null,
            'last_login' => now(),
            'last_activity' => now(),
            'ip_address' => $request->ip()
        ]);

        // Generate OTP for mandatory 2FA
        $otpCode = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        // Store OTP in database
        try {
            // Delete old OTPs for this user
            \DB::table('centralized_admin_otp')
                ->where('admin_id', $user->id)
                ->delete();

            // Insert new OTP
            $otpInserted = \DB::table('centralized_admin_otp')->insert([
                'admin_id' => $user->id,
                'otp_code' => $otpCode,
                'created_at' => now(),
                'expires_at' => now()->addMinutes(5)
            ]);

            if (!$otpInserted) {
                \Log::error('Failed to insert OTP for user: ' . $user->id);
                if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                    return response()->json(['message' => 'Failed to generate OTP. Please try again.'], 500);
                }
                return redirect()->back()->withErrors(['email' => 'Failed to generate OTP. Please try again.']);
            }

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
                \Log::info('OTP sent successfully to: ' . $user->email);
            } catch (\Exception $e) {
                \Log::error('Failed to send OTP email: ' . $e->getMessage());
                // Continue anyway - user can still enter OTP manually
            }

            // Set session
            session(['otp_admin_id' => $user->id]);

            if ($request->expectsJson() || $request->header('X-Requested-With') === 'XMLHttpRequest') {
                return response()->json(['success' => true], 200);
            }

            return redirect()->route('otp.verify');
        } catch (\Exception $e) {
            \Log::error('Error during OTP generation: ' . $e->getMessage());
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

            // Clean up old OTPs
            \DB::table('centralized_admin_otp')
                ->where('admin_id', $adminId)
                ->delete();

            // Generate new OTP
            $otpCode = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

            // Store new OTP
            $otpInserted = \DB::table('centralized_admin_otp')->insert([
                'admin_id' => $adminId,
                'otp_code' => $otpCode,
                'created_at' => now(),
                'expires_at' => now()->addMinutes(5)
            ]);

            if (!$otpInserted) {
                \Log::error('Failed to insert new OTP for user: ' . $adminId);
                return response()->json([
                    'success' => false,
                    'error' => 'Failed to generate new OTP. Please try again.'
                ], 500);
            }

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
                \Log::info('New OTP sent successfully to: ' . $user->email);
            } catch (\Exception $e) {
                \Log::error('Failed to send new OTP email: ' . $e->getMessage());
                // Continue anyway - user can still enter OTP manually
            }

            return response()->json([
                'success' => true,
                'message' => 'New OTP sent successfully'
            ]);
        } catch (\Exception $e) {
            \Log::error('Error during OTP resend: ' . $e->getMessage());
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

        $otpRecord = \DB::table('centralized_admin_otp')
            ->where('admin_id', $adminId)
            ->where('expires_at', '>', now())
            ->first();

        if (!$otpRecord || $request->otp !== $otpRecord->otp_code) {
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

        // Clean up OTP
        \DB::table('centralized_admin_otp')
            ->where('admin_id', $adminId)
            ->delete();

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
            // Super admin gets special subdomain
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
        $user = CentralizedAdminUser::where('unlock_token', $token)
            ->where('unlock_token_expiry', '>', now())
            ->first();

        if (!$user) {
            return redirect('/')->withErrors(['email' => 'Invalid or expired unlock link.']);
        }

        // Unlock the account
        $user->update([
            'attempt_count' => 0,
            'unlock_token' => null,
            'unlock_token_expiry' => null
        ]);

        return redirect('/')->with('success', 'Your account has been unlocked successfully. You can now login.');
    }

    public function logout()
    {
        Auth::logout();
        session()->invalidate();
        session()->regenerateToken();

        return redirect('/');
    }
}
