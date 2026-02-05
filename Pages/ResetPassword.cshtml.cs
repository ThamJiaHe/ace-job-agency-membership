using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
        private readonly IEmailService _emailService;
        private readonly AuthDbContext _context;
        private readonly ILogger<ResetPasswordModel> _logger;

        private const int PasswordHistoryLimit = 2;

        public ResetPasswordModel(
            UserManager<ApplicationUser> userManager,
            IPasswordHasher<ApplicationUser> passwordHasher,
            IEmailService emailService,
            AuthDbContext context,
            ILogger<ResetPasswordModel> logger)
        {
            _userManager = userManager;
            _passwordHasher = passwordHasher;
            _emailService = emailService;
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public bool ResetSuccess { get; set; }
        public bool InvalidLink { get; set; }
        public string? ErrorMessage { get; set; }

        public class InputModel
        {
            public string UserId { get; set; } = string.Empty;
            public string Token { get; set; } = string.Empty;

            [Required(ErrorMessage = "New password is required")]
            [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters")]
            [DataType(DataType.Password)]
            [Display(Name = "New Password")]
            public string NewPassword { get; set; } = string.Empty;

            [Required(ErrorMessage = "Please confirm your new password")]
            [DataType(DataType.Password)]
            [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
            [Display(Name = "Confirm Password")]
            public string ConfirmPassword { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnGetAsync(string? userId, string? token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                InvalidLink = true;
                ErrorMessage = "Invalid password reset link. Please request a new one.";
                return Page();
            }

            // Verify user exists
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                InvalidLink = true;
                ErrorMessage = "Invalid password reset link. The account may not exist.";
                return Page();
            }

            // Store in input model for form submission
            Input.UserId = userId;
            Input.Token = token;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Server-side password complexity validation
            if (!ValidatePasswordComplexity(Input.NewPassword))
            {
                ModelState.AddModelError("Input.NewPassword",
                    "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*)");
                return Page();
            }

            // Find user
            var user = await _userManager.FindByIdAsync(Input.UserId);
            if (user == null)
            {
                InvalidLink = true;
                ErrorMessage = "Invalid password reset request.";
                return Page();
            }

            // Check password history - prevent reuse of last 2 passwords
            if (IsPasswordInHistorySync(user, Input.NewPassword))
            {
                ModelState.AddModelError("Input.NewPassword",
                    "You cannot reuse any of your last 2 passwords. Please choose a different password.");
                return Page();
            }

            try
            {
                // Save current password to history BEFORE reset
                await SavePasswordToHistory(user);

                // Decode the token
                var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(Input.Token));

                // Reset password
                var result = await _userManager.ResetPasswordAsync(user, decodedToken, Input.NewPassword);

                if (result.Succeeded)
                {
                    _logger.LogInformation("Password reset successful for user {Email}", user.Email);

                    // Update LastPasswordChange timestamp
                    user.LastPasswordChange = DateTime.Now;
                    await _userManager.UpdateAsync(user);

                    // Log audit
                    _context.AuditLogs.Add(new AuditLog
                    {
                        UserId = user.Id,
                        Action = "Password Reset Completed",
                        Timestamp = DateTime.Now,
                        IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                    });
                    await _context.SaveChangesAsync();

                    // Send confirmation email
                    try
                    {
                        await _emailService.SendPasswordChangedNotificationAsync(
                            user.Email!,
                            user.FirstName ?? "User"
                        );
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to send password changed notification to {Email}", user.Email);
                    }

                    ResetSuccess = true;
                    return Page();
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        // Check for specific error types
                        if (error.Code.Contains("Token"))
                        {
                            InvalidLink = true;
                            ErrorMessage = "The password reset link has expired or has already been used. Please request a new one.";
                            return Page();
                        }

                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }
            catch (FormatException)
            {
                InvalidLink = true;
                ErrorMessage = "Invalid password reset link format. Please request a new one.";
                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password reset for user {UserId}", Input.UserId);
                InvalidLink = true;
                ErrorMessage = "An error occurred. Please try requesting a new password reset link.";
                return Page();
            }

            return Page();
        }

        /// <summary>
        /// Server-side password complexity validation (From Practical 2)
        /// </summary>
        private bool ValidatePasswordComplexity(string password)
        {
            if (string.IsNullOrEmpty(password) || password.Length < 12)
                return false;

            int score = 0;

            if (Regex.IsMatch(password, @"[a-z]")) score++;
            if (Regex.IsMatch(password, @"[A-Z]")) score++;
            if (Regex.IsMatch(password, @"\d")) score++;
            if (Regex.IsMatch(password, @"[!@#$%^&*]")) score++;
            if (password.Length >= 12) score++;

            return score >= 5;
        }

        /// <summary>
        /// Check if the new password matches any of the user's previous passwords
        /// </summary>
        private bool IsPasswordInHistorySync(ApplicationUser user, string newPassword)
        {
            var passwordHistory = _context.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(PasswordHistoryLimit)
                .ToList();

            foreach (var history in passwordHistory)
            {
                var verifyResult = _passwordHasher.VerifyHashedPassword(user, history.PasswordHash, newPassword);
                if (verifyResult == PasswordVerificationResult.Success ||
                    verifyResult == PasswordVerificationResult.SuccessRehashNeeded)
                {
                    _logger.LogWarning("User {Email} attempted to reuse a previous password during reset", user.Email);
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Save the current password to history before changing
        /// </summary>
        private async Task SavePasswordToHistory(ApplicationUser user)
        {
            if (user.PasswordHash == null) return;

            _context.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash,
                CreatedAt = DateTime.Now
            });

            // Remove old entries beyond the limit
            var oldEntries = _context.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Skip(PasswordHistoryLimit)
                .ToList();

            if (oldEntries.Any())
            {
                _context.PasswordHistories.RemoveRange(oldEntries);
            }

            await _context.SaveChangesAsync();
        }
    }
}
