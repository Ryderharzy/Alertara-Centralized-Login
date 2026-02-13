<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

// Main index page (login form)
Route::get('/', [AuthController::class, 'showLogin'])->name('login.show');

// Authentication routes
Route::post('/login', [AuthController::class, 'login'])->name('login.submit');
Route::get('/unlock-account/{token}', [AuthController::class, 'unlockAccount'])->name('unlock-account');
Route::get('/otp/verify', [AuthController::class, 'verifyOTP'])->name('otp.verify');
Route::post('/otp/verify', [AuthController::class, 'submitOTP'])->name('otp.submit');
Route::post('/otp/resend', [AuthController::class, 'resendOTP'])->name('otp.resend');
Route::post('/logout', [AuthController::class, 'logout'])->name('logout');

// Protected routes
Route::middleware(['auth'])->group(function () {
    Route::get('/dashboard', function () {
        return view('dashboard');
    })->name('dashboard');
});
