<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Code</title>
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
        .code-box {
            background-color: #f9f9f9;
            border: 2px solid #999;
            border-radius: 4px;
            padding: 20px;
            text-align: center;
            margin: 24px 0;
        }
        .code {
            font-size: 40px;
            font-weight: bold;
            color: #4c8a89;
            letter-spacing: 4px;
            font-family: 'Courier New', monospace;
            margin: 0;
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
            <h1>Verification Code</h1>
        </div>

        <div class="content">
            <p>Hi {{ $user->email }},</p>

            <p>We've detected a login attempt to your account. To verify it's you, please use the code below:</p>

            <div class="code-box">
                <p class="code">{{ $otpCode }}</p>
            </div>

            <p>Enter this code on the verification page. This code will expire in 1 minute.</p>

            <p style="font-size: 12px; color: #999; margin-top: 24px;">If you didn't attempt this login, please ignore this email. Your account will remain secure.</p>
        </div>

        <div class="footer">
            <p>&copy; {{ date('Y') }} AlerTaraQC. All rights reserved.</p>
            <p>This is an automated security email. Please do not reply to this message.</p>
        </div>
    </div>
</body>
</html>
