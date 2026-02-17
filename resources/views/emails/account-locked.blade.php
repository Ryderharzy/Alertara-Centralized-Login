<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Locked</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 500px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        .header {
            background-color: #f5f5f5;
            padding: 30px 20px;
            text-align: center;
            border-bottom: 2px solid #ddd;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
            color: #333;
        }
        .content {
            padding: 30px 25px;
        }
        .content p {
            margin: 12px 0;
            color: #555;
        }
        .button {
            display: inline-block;
            width: 100%;
            text-align: center;
            background-color: #4c8a89;
            color: #fff !important;
            text-decoration: none !important;
            padding: 14px;
            border-radius: 4px;
            font-weight: 500;
            margin: 24px 0;
            box-sizing: border-box;
        }
        .button:hover {
            background-color: #3a6b6a;
        }
        .footer {
            background-color: #f5f5f5;
            border-top: 1px solid #ddd;
            padding: 20px 25px;
            text-align: center;
            font-size: 12px;
            color: #999;
        }
        .footer p {
            margin: 4px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Account Locked</h1>
        </div>

        <div class="content">
            <p>Hi {{ $user->full_name }},</p>

            <p>Your account has been temporarily locked after 3 failed login attempts. This is a security measure to protect your account.</p>

            <p>Click the button below to unlock your account:</p>

            <a href="{{ route('unlock-account', ['token' => $unlockToken, 'email' => $user->email]) }}" class="button">Unlock Account</a>

            <p style="font-size: 12px; color: #999;">This link expires in 1 hour. If you didn't attempt this login, please contact support.</p>
        </div>

        <div class="footer">
            <p>&copy; {{ date('Y') }} AlerTaraQC. All rights reserved.</p>
            <p>This is an automated security email. Please do not reply to this message.</p>
        </div>
    </div>
</body>
</html>
