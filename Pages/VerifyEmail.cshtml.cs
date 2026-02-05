using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using AceJobAgency.Models;

namespace AceJobAgency.Pages
{
    public class VerifyEmailModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _context;
        private readonly ILogger<VerifyEmailModel> _logger;

        public VerifyEmailModel(
            UserManager<ApplicationUser> userManager,
            AuthDbContext context,
            ILogger<VerifyEmailModel> logger)
        {
            _userManager = userManager;
            _context = context;
            _logger = logger;
        }

        public bool IsSuccess { get; set; }
        public string? ErrorMessage { get; set; }

        public async Task<IActionResult> OnGetAsync(string? userId, string? token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                IsSuccess = false;
                ErrorMessage = "Invalid verification link. The link may be malformed or incomplete.";
                return Page();
            }

            // Find user by ID
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                IsSuccess = false;
                ErrorMessage = "User not found. The account may have been deleted.";
                return Page();
            }

            // Check if already verified
            if (user.EmailConfirmed)
            {
                IsSuccess = true;
                return Page();
            }

            try
            {
                // Decode the token
                var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));

                // Confirm email
                var result = await _userManager.ConfirmEmailAsync(user, decodedToken);

                if (result.Succeeded)
                {
                    IsSuccess = true;
                    _logger.LogInformation("Email verified for user {Email}", user.Email);

                    // Log audit
                    _context.AuditLogs.Add(new AuditLog
                    {
                        UserId = user.Id,
                        Action = "Email Verified",
                        Timestamp = DateTime.Now,
                        IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                    });
                    await _context.SaveChangesAsync();
                }
                else
                {
                    IsSuccess = false;
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    ErrorMessage = "Verification failed. The link may have expired or already been used.";
                    _logger.LogWarning("Email verification failed for {Email}: {Errors}", user.Email, errors);
                }
            }
            catch (Exception ex)
            {
                IsSuccess = false;
                ErrorMessage = "Invalid verification link. Please request a new verification email.";
                _logger.LogError(ex, "Error during email verification for user {UserId}", userId);
            }

            return Page();
        }
    }
}
