using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    /// <summary>
    /// Change Password page - allows logged-in users to change their password
    /// Assignment Advanced Feature: Change password while logged in
    /// </summary>
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
        private readonly AuthDbContext _context;
        private readonly IEmailService _emailService;
        private readonly ILogger<ChangePasswordModel> _logger;
        private readonly IConfiguration _configuration;

        // Number of previous passwords to check (assignment requires 2)
        private const int PasswordHistoryLimit = 2;

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IPasswordHasher<ApplicationUser> passwordHasher,
            AuthDbContext context,
            IEmailService emailService,
            ILogger<ChangePasswordModel> logger,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _passwordHasher = passwordHasher;
            _context = context;
            _emailService = emailService;
            _logger = logger;
            _configuration = configuration;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public bool ChangeSuccess { get; set; }
        public bool PasswordExpired { get; set; }
        public string? MinAgeMessage { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Current password is required")]
            [DataType(DataType.Password)]
            [Display(Name = "Current Password")]
            public string CurrentPassword { get; set; } = string.Empty;

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

        public void OnGet(bool? expired)
        {
            // Check if user was redirected due to expired password
            if (expired == true)
            {
                PasswordExpired = true;
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            // Check minimum password age - prevent changing password too frequently
            var minPasswordAgeDays = _configuration.GetValue<int>("PasswordPolicy:MinPasswordAgeDays", 1);
            var timeSinceLastChange = DateTime.Now - user.LastPasswordChange;
            if (timeSinceLastChange.TotalDays < minPasswordAgeDays)
            {
                var hoursRemaining = (int)Math.Ceiling((minPasswordAgeDays * 24) - timeSinceLastChange.TotalHours);
                MinAgeMessage = $"You must wait at least {minPasswordAgeDays} day(s) before changing your password. Please try again in {hoursRemaining} hour(s).";
                _logger.LogWarning("User {Email} attempted to change password before minimum age ({Days} days)",
                    user.Email, minPasswordAgeDays);
                ModelState.AddModelError(string.Empty, MinAgeMessage);
                return Page();
            }

            // Server-side password complexity validation
            if (!ValidatePasswordComplexity(Input.NewPassword))
            {
                ModelState.AddModelError("Input.NewPassword",
                    "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*)");
                return Page();
            }

            // Check if new password is same as current
            if (Input.CurrentPassword == Input.NewPassword)
            {
                ModelState.AddModelError("Input.NewPassword",
                    "New password must be different from your current password.");
                return Page();
            }

            // Check password history - prevent reuse of last 2 passwords
            if (IsPasswordInHistorySync(user, Input.NewPassword))
            {
                ModelState.AddModelError("Input.NewPassword",
                    "You cannot reuse any of your last 2 passwords. Please choose a different password.");
                return Page();
            }

            // Attempt to change password
            var result = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);

            if (result.Succeeded)
            {
                _logger.LogInformation("Password changed successfully for user {Email}", user.Email);

                // Save current password to history BEFORE the change takes effect
                await SavePasswordToHistory(user);

                // Update LastPasswordChange timestamp
                user.LastPasswordChange = DateTime.Now;
                await _userManager.UpdateAsync(user);

                // Log audit
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "Password Changed",
                    Timestamp = DateTime.Now,
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                });
                await _context.SaveChangesAsync();

                // Send notification email
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

                // Refresh sign-in to update security stamp
                await _signInManager.RefreshSignInAsync(user);

                ChangeSuccess = true;
                return Page();
            }

            // Handle errors
            foreach (var error in result.Errors)
            {
                if (error.Code == "PasswordMismatch")
                {
                    ModelState.AddModelError("Input.CurrentPassword", "Current password is incorrect.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return Page();
        }

        /// <summary>
        /// Check if the new password matches any of the user's previous passwords
        /// </summary>
        private bool IsPasswordInHistorySync(ApplicationUser user, string newPassword)
        {
            // Get the user's password history (most recent first)
            var passwordHistory = _context.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(PasswordHistoryLimit)
                .ToList();

            foreach (var history in passwordHistory)
            {
                // Check if the new password matches any historical password
                var verifyResult = _passwordHasher.VerifyHashedPassword(user, history.PasswordHash, newPassword);
                if (verifyResult == PasswordVerificationResult.Success ||
                    verifyResult == PasswordVerificationResult.SuccessRehashNeeded)
                {
                    _logger.LogWarning("User {Email} attempted to reuse a previous password", user.Email);
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
            // Get fresh user data to ensure we have the current password hash
            var freshUser = await _userManager.FindByIdAsync(user.Id);
            if (freshUser?.PasswordHash == null) return;

            // Add current password to history
            _context.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = freshUser.PasswordHash,
                CreatedAt = DateTime.Now
            });

            // Remove old password history entries beyond the limit
            var oldHistoryEntries = _context.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Skip(PasswordHistoryLimit)
                .ToList();

            if (oldHistoryEntries.Any())
            {
                _context.PasswordHistories.RemoveRange(oldHistoryEntries);
            }

            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// Server-side password complexity validation
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
    }
}
