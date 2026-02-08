using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Models;

namespace AceJobAgency.Pages
{
    public class TwoFactorLoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _context;
        private readonly ILogger<TwoFactorLoginModel> _logger;

        public TwoFactorLoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthDbContext context,
            ILogger<TwoFactorLoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public bool RememberMe { get; set; }
        public string? ReturnUrl { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Verification code is required")]
            [StringLength(7, MinimumLength = 6, ErrorMessage = "Code must be 6-7 characters")]
            [Display(Name = "Authenticator Code")]
            public string TwoFactorCode { get; set; } = string.Empty;

            [Display(Name = "Remember this device")]
            public bool RememberMachine { get; set; }
        }

        public async Task<IActionResult> OnGetAsync(bool rememberMe, string? returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                _logger.LogWarning("2FA login page accessed without completing password authentication");
                return RedirectToPage("/Login");
            }

            RememberMe = rememberMe;
            ReturnUrl = returnUrl;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(bool rememberMe, string? returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                _logger.LogWarning("2FA verification attempted without authenticated user");
                return RedirectToPage("/Login");
            }

            var ipAddress = GetClientIpAddress();

            // Strip spaces and hyphens
            var authenticatorCode = Input.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
                authenticatorCode, rememberMe, Input.RememberMachine);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} logged in with 2FA", user.Email);

                // Handle multiple login detection - terminate old sessions
                await HandleMultipleLoginDetection(user, ipAddress);

                // Create session after 2FA
                await CreateNewSession(user, ipAddress);

                // Log audit
                await LogAuditAsync(user.Id, "Login Success with 2FA", ipAddress);

                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    return LocalRedirect(returnUrl);
                }

                return RedirectToPage("/Index");
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User {Email} account locked out after failed 2FA", user.Email);
                await LogAuditAsync(user.Id, "Account Locked - Failed 2FA Attempts", ipAddress);
                return RedirectToPage("/Lockout");
            }
            else
            {
                _logger.LogWarning("Invalid 2FA code entered for user {Email}", user.Email);
                await LogAuditAsync(user.Id, "2FA Failed - Invalid Code", ipAddress);
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return Page();
            }
        }

        public async Task<IActionResult> OnPostUseRecoveryCodeAsync(bool rememberMe, string? returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            var ipAddress = GetClientIpAddress();

            // Strip spaces and hyphens
            var recoveryCode = Input.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} logged in with recovery code", user.Email);

                // Handle multiple login detection - terminate old sessions
                await HandleMultipleLoginDetection(user, ipAddress);

                await CreateNewSession(user, ipAddress);
                await LogAuditAsync(user.Id, "Login Success with Recovery Code", ipAddress);

                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    return LocalRedirect(returnUrl);
                }

                return RedirectToPage("/Index");
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User {Email} account locked out", user.Email);
                await LogAuditAsync(user.Id, "Account Locked - Failed Recovery Code", ipAddress);
                return RedirectToPage("/Lockout");
            }
            else
            {
                _logger.LogWarning("Invalid recovery code entered for user {Email}", user.Email);
                await LogAuditAsync(user.Id, "2FA Failed - Invalid Recovery Code", ipAddress);
                ModelState.AddModelError(string.Empty, "Invalid recovery code.");
                return Page();
            }
        }

        /// <summary>
        /// Handle multiple login detection - terminate old sessions
        /// </summary>
        private async Task HandleMultipleLoginDetection(ApplicationUser user, string ipAddress)
        {
            var existingSessions = _context.ActiveSessions
                .Where(s => s.UserId == user.Id)
                .ToList();

            if (existingSessions.Any())
            {
                _logger.LogInformation("Multiple login detected for user {Email}. Terminating {Count} old session(s)",
                    user.Email, existingSessions.Count);

                foreach (var session in existingSessions)
                {
                    await LogAuditAsync(user.Id,
                        $"Multiple Login - Old Session Terminated (IP: {session.IpAddress})", ipAddress);
                }

                _context.ActiveSessions.RemoveRange(existingSessions);
                await _context.SaveChangesAsync();
            }
        }

        private async Task CreateNewSession(ApplicationUser user, string ipAddress)
        {
            var sessionId = Guid.NewGuid().ToString();
            var authToken = Guid.NewGuid().ToString();

            var newSession = new ActiveSession
            {
                UserId = user.Id,
                SessionId = sessionId,
                LoginTime = DateTime.Now,
                IpAddress = ipAddress
            };

            _context.ActiveSessions.Add(newSession);
            await _context.SaveChangesAsync();

            HttpContext.Session.SetString("SessionId", sessionId);
            HttpContext.Session.SetString("UserId", user.Id);
            HttpContext.Session.SetString("UserEmail", user.Email ?? "");
            HttpContext.Session.SetString("UserName", $"{user.FirstName} {user.LastName}");
            HttpContext.Session.SetString("AuthToken", authToken);

            Response.Cookies.Append("AuthToken", authToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.Now.AddMinutes(20)
            });
        }

        private async Task LogAuditAsync(string userId, string action, string ipAddress)
        {
            var log = new AuditLog
            {
                UserId = userId,
                Action = action,
                Timestamp = DateTime.Now,
                IpAddress = ipAddress
            };

            _context.AuditLogs.Add(log);
            await _context.SaveChangesAsync();
        }

        private string GetClientIpAddress()
        {
            var forwardedFor = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                return forwardedFor.Split(',')[0].Trim();
            }
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }
    }
}
