using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _context;
        private readonly ILogger<LoginModel> _logger;
        private readonly IRecaptchaService _recaptchaService;
        private readonly IConfiguration _configuration;

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthDbContext context,
            ILogger<LoginModel> logger,
            IRecaptchaService recaptchaService,
            IConfiguration configuration)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _context = context;
            _logger = logger;
            _recaptchaService = recaptchaService;
            _configuration = configuration;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        [BindProperty]
        public string? RecaptchaToken { get; set; }

        public bool IsLockedOut { get; set; }
        public int LockoutMinutesRemaining { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Email is required")]
            [EmailAddress(ErrorMessage = "Invalid email address")]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "Password is required")]
            [DataType(DataType.Password)]
            public string Password { get; set; } = string.Empty;

            public bool RememberMe { get; set; }
        }

        public IActionResult OnGet()
        {
            // If already logged in, redirect to homepage
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToPage("/Index");
            }

            // Check if there's a returnUrl in query string
            if (Request.Query.ContainsKey("ReturnUrl"))
            {
                TempData["ReturnUrl"] = Request.Query["ReturnUrl"].ToString();
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var ipAddress = GetClientIpAddress();

            // Verify reCAPTCHA v3 token
            var recaptchaResult = await _recaptchaService.VerifyAsync(RecaptchaToken ?? "", "login");
            if (!recaptchaResult.Success)
            {
                _logger.LogWarning("reCAPTCHA verification failed for login attempt from {IP}. Score: {Score}",
                    ipAddress, recaptchaResult.Score);

                // Log failed reCAPTCHA attempt to audit log
                await LogAuditAsync(null, $"Login Failed - reCAPTCHA: {recaptchaResult.ErrorMessage}",
                    ipAddress, Input.Email);

                ModelState.AddModelError(string.Empty,
                    recaptchaResult.ErrorMessage ?? "Security verification failed. Please try again.");
                return Page();
            }

            _logger.LogInformation("reCAPTCHA passed for login. Score: {Score}", recaptchaResult.Score);

            // Find user by email
            var user = await _userManager.FindByEmailAsync(Input.Email);

            if (user == null)
            {
                // Don't reveal that the user doesn't exist
                await LogAuditAsync(null, "Login Failed - User Not Found", ipAddress, Input.Email);
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
                return Page();
            }

            // Check if email is verified
            if (!user.EmailConfirmed)
            {
                await LogAuditAsync(user.Id, "Login Failed - Email Not Verified", ipAddress);
                ModelState.AddModelError(string.Empty,
                    "Please verify your email before logging in. Check your inbox for the verification link.");
                return Page();
            }

            // Check if account is locked out BEFORE attempting sign-in
            if (await _userManager.IsLockedOutAsync(user))
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                if (lockoutEnd.HasValue)
                {
                    var remaining = lockoutEnd.Value - DateTimeOffset.UtcNow;
                    LockoutMinutesRemaining = Math.Max(1, (int)Math.Ceiling(remaining.TotalMinutes));
                }
                IsLockedOut = true;

                await LogAuditAsync(user.Id, "Login Failed - Account Locked", ipAddress);
                _logger.LogWarning("Locked out user {Email} attempted login", Input.Email);

                return Page();
            }

            // Attempt sign-in with lockout enabled
            var result = await _signInManager.PasswordSignInAsync(
                Input.Email,
                Input.Password,
                Input.RememberMe,
                lockoutOnFailure: true  // Enable lockout on failure
            );

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} logged in successfully", Input.Email);

                // Check maximum password age - force password change if expired
                var maxPasswordAgeDays = _configuration.GetValue<int>("PasswordPolicy:MaxPasswordAgeDays", 90);
                var daysSincePasswordChange = (DateTime.Now - user.LastPasswordChange).TotalDays;

                if (daysSincePasswordChange > maxPasswordAgeDays)
                {
                    _logger.LogWarning("User {Email} password has expired ({Days} days old, max is {Max})",
                        user.Email, (int)daysSincePasswordChange, maxPasswordAgeDays);

                    // Log audit for expired password
                    await LogAuditAsync(user.Id, $"Password Expired - Forced Change Required ({(int)daysSincePasswordChange} days old)", ipAddress);

                    // Handle multiple login detection and create session before redirect
                    await HandleMultipleLoginDetection(user, ipAddress);
                    await CreateNewSession(user, ipAddress);

                    // Redirect to change password page with expired flag
                    return RedirectToPage("/ChangePassword", new { expired = true });
                }

                // Handle multiple login detection
                await HandleMultipleLoginDetection(user, ipAddress);

                // Create new session
                await CreateNewSession(user, ipAddress);

                // Log successful login
                await LogAuditAsync(user.Id, "Login Success", ipAddress);

                // Redirect to return URL or homepage
                var returnUrl = TempData["ReturnUrl"]?.ToString();
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    return LocalRedirect(returnUrl);
                }

                return RedirectToPage("/Index");
            }

            if (result.IsLockedOut)
            {
                IsLockedOut = true;
                LockoutMinutesRemaining = 5; // Default lockout time

                await LogAuditAsync(user.Id, "Login Failed - Account Now Locked", ipAddress);
                _logger.LogWarning("User {Email} account locked out after failed attempts", Input.Email);

                return Page();
            }

            if (result.RequiresTwoFactor)
            {
                _logger.LogInformation("User {Email} requires 2FA verification", Input.Email);
                await LogAuditAsync(user.Id, "Login - 2FA Required", ipAddress);

                var returnUrl = TempData["ReturnUrl"]?.ToString();
                return RedirectToPage("/TwoFactorLogin", new {
                    rememberMe = Input.RememberMe,
                    returnUrl = returnUrl
                });
            }

            // Failed login - invalid credentials
            var failedAttempts = await _userManager.GetAccessFailedCountAsync(user);
            var attemptsRemaining = 3 - failedAttempts;

            await LogAuditAsync(user.Id, $"Login Failed - Invalid Password (Attempt {failedAttempts}/3)", ipAddress);
            _logger.LogWarning("Failed login attempt for {Email}. Attempts: {Attempts}/3", Input.Email, failedAttempts);

            if (attemptsRemaining > 0)
            {
                ModelState.AddModelError(string.Empty,
                    $"Invalid email or password. {attemptsRemaining} attempt(s) remaining before account lockout.");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
            }

            return Page();
        }

        /// <summary>
        /// Handle multiple login detection - terminate old sessions
        /// From Practical 4: Detect and handle multiple logins
        /// </summary>
        private async Task HandleMultipleLoginDetection(ApplicationUser user, string ipAddress)
        {
            // Check for existing active sessions for this user
            var existingSessions = _context.ActiveSessions
                .Where(s => s.UserId == user.Id)
                .ToList();

            if (existingSessions.Any())
            {
                _logger.LogInformation("Multiple login detected for user {Email}. Terminating {Count} old session(s)",
                    user.Email, existingSessions.Count);

                // Log audit for each terminated session
                foreach (var session in existingSessions)
                {
                    await LogAuditAsync(user.Id,
                        $"Multiple Login - Old Session Terminated (IP: {session.IpAddress})", ipAddress);
                }

                // Remove all old sessions
                _context.ActiveSessions.RemoveRange(existingSessions);
                await _context.SaveChangesAsync();
            }
        }

        /// <summary>
        /// Create a new session entry and store session ID
        /// From Practical 4: Session Fixation Prevention - use BOTH session AND cookie
        /// </summary>
        private async Task CreateNewSession(ApplicationUser user, string ipAddress)
        {
            // Generate new session ID
            var sessionId = Guid.NewGuid().ToString();

            // Generate AuthToken for session fixation prevention (From Practical 4)
            var authToken = Guid.NewGuid().ToString();

            // Create session record in database
            var newSession = new ActiveSession
            {
                UserId = user.Id,
                SessionId = sessionId,
                LoginTime = DateTime.Now,
                IpAddress = ipAddress
            };

            _context.ActiveSessions.Add(newSession);
            await _context.SaveChangesAsync();

            // Store session info in HttpContext.Session
            HttpContext.Session.SetString("SessionId", sessionId);
            HttpContext.Session.SetString("UserId", user.Id);
            HttpContext.Session.SetString("UserEmail", user.Email ?? "");
            HttpContext.Session.SetString("UserName", $"{user.FirstName} {user.LastName}");

            // From Practical 4: Store AuthToken in BOTH session AND cookie
            // This prevents session fixation attacks
            HttpContext.Session.SetString("AuthToken", authToken);
            Response.Cookies.Append("AuthToken", authToken, new CookieOptions
            {
                HttpOnly = true,    // Prevent XSS access to cookie
                Secure = true,      // Only send over HTTPS
                SameSite = SameSiteMode.Strict,  // Prevent CSRF
                Expires = DateTimeOffset.Now.AddMinutes(20)  // Match session timeout
            });

            _logger.LogInformation("New session created for user {Email}: {SessionId}", user.Email, sessionId);
        }

        /// <summary>
        /// Log user activities to AuditLog table
        /// </summary>
        private async Task LogAuditAsync(string? userId, string action, string ipAddress, string? email = null)
        {
            var log = new AuditLog
            {
                UserId = userId ?? email ?? "Unknown",
                Action = action,
                Timestamp = DateTime.Now,
                IpAddress = ipAddress
            };

            _context.AuditLogs.Add(log);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Audit: {Action} for user {UserId} from {IP}",
                action, userId ?? email ?? "Unknown", ipAddress);
        }

        /// <summary>
        /// Get client IP address
        /// </summary>
        private string GetClientIpAddress()
        {
            // Check for forwarded IP (if behind proxy/load balancer)
            var forwardedFor = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                return forwardedFor.Split(',')[0].Trim();
            }

            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }
    }
}
