using Resend;

namespace AceJobAgency.Services
{
    /// <summary>
    /// Email service implementation using Resend API
    /// For password reset and email verification
    /// </summary>
    public class EmailService : IEmailService
    {
        private readonly IResend _resend;
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;
        private readonly string _fromEmail;

        public EmailService(IResend resend, IConfiguration configuration, ILogger<EmailService> logger)
        {
            _resend = resend;
            _configuration = configuration;
            _logger = logger;
            _fromEmail = _configuration["Resend:FromEmail"] ?? "onboarding@resend.dev";
        }

        public async Task SendEmailVerificationAsync(string toEmail, string userName, string verificationLink)
        {
            var subject = "Verify Your Ace Job Agency Account";
            var htmlBody = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }}
        .button {{ display: inline-block; background: #2563eb; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0; }}
        .footer {{ text-align: center; margin-top: 20px; color: #64748b; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Welcome to Ace Job Agency!</h1>
        </div>
        <div class='content'>
            <p>Hi {userName},</p>
            <p>Thank you for registering with Ace Job Agency. Please verify your email address by clicking the button below:</p>
            <p style='text-align: center;'>
                <a href='{verificationLink}' class='button'>Verify Email Address</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style='word-break: break-all; color: #2563eb;'>{verificationLink}</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you didn't create an account with us, please ignore this email.</p>
        </div>
        <div class='footer'>
            <p>&copy; {DateTime.Now.Year} Ace Job Agency. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

            await SendEmailAsync(toEmail, subject, htmlBody);
            _logger.LogInformation("Verification email sent to {Email}", toEmail);
        }

        public async Task SendPasswordResetAsync(string toEmail, string userName, string resetLink)
        {
            var subject = "Reset Your Ace Job Agency Password";
            var htmlBody = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }}
        .button {{ display: inline-block; background: #f59e0b; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0; }}
        .warning {{ background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .footer {{ text-align: center; margin-top: 20px; color: #64748b; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Password Reset Request</h1>
        </div>
        <div class='content'>
            <p>Hi {userName},</p>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <p style='text-align: center;'>
                <a href='{resetLink}' class='button'>Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style='word-break: break-all; color: #f59e0b;'>{resetLink}</p>
            <div class='warning'>
                <strong>⚠️ Important:</strong>
                <ul>
                    <li>This link will expire in <strong>1 hour</strong></li>
                    <li>If you didn't request this reset, please ignore this email</li>
                    <li>Your password will remain unchanged until you create a new one</li>
                </ul>
            </div>
        </div>
        <div class='footer'>
            <p>&copy; {DateTime.Now.Year} Ace Job Agency. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

            await SendEmailAsync(toEmail, subject, htmlBody);
            _logger.LogInformation("Password reset email sent to {Email}", toEmail);
        }

        public async Task SendPasswordChangedNotificationAsync(string toEmail, string userName)
        {
            var subject = "Your Ace Job Agency Password Has Been Changed";
            var htmlBody = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }}
        .warning {{ background: #fef2f2; border: 1px solid #ef4444; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .footer {{ text-align: center; margin-top: 20px; color: #64748b; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Password Changed Successfully</h1>
        </div>
        <div class='content'>
            <p>Hi {userName},</p>
            <p>Your password for Ace Job Agency has been successfully changed.</p>
            <p><strong>Date/Time:</strong> {DateTime.Now:dddd, MMMM d, yyyy 'at' h:mm tt}</p>
            <div class='warning'>
                <strong>⚠️ Didn't make this change?</strong>
                <p>If you didn't change your password, your account may have been compromised. Please:</p>
                <ol>
                    <li>Reset your password immediately</li>
                    <li>Contact our support team</li>
                    <li>Review your account activity</li>
                </ol>
            </div>
        </div>
        <div class='footer'>
            <p>&copy; {DateTime.Now.Year} Ace Job Agency. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

            await SendEmailAsync(toEmail, subject, htmlBody);
            _logger.LogInformation("Password changed notification sent to {Email}", toEmail);
        }

        /// <summary>
        /// Internal method to send email via Resend API
        /// </summary>
        private async Task SendEmailAsync(string toEmail, string subject, string htmlBody)
        {
            try
            {
                var message = new EmailMessage();
                message.From = _fromEmail;
                message.To.Add(toEmail);
                message.Subject = subject;
                message.HtmlBody = htmlBody;

                await _resend.EmailSendAsync(message);

                _logger.LogInformation("Email sent successfully to {Email}", toEmail);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email}", toEmail);
                throw new InvalidOperationException($"Failed to send email: {ex.Message}", ex);
            }
        }
    }
}
