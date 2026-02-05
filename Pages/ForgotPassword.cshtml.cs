using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        private readonly AuthDbContext _context;
        private readonly ILogger<ForgotPasswordModel> _logger;

        public ForgotPasswordModel(
            UserManager<ApplicationUser> userManager,
            IEmailService emailService,
            IConfiguration configuration,
            AuthDbContext context,
            ILogger<ForgotPasswordModel> logger)
        {
            _userManager = userManager;
            _emailService = emailService;
            _configuration = configuration;
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public bool EmailSent { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Email address is required")]
            [EmailAddress(ErrorMessage = "Please enter a valid email address")]
            public string Email { get; set; } = string.Empty;
        }

        public void OnGet()
        {
            EmailSent = false;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);

            // Always show success message to prevent email enumeration attacks
            // This is a security best practice
            if (user == null)
            {
                _logger.LogInformation("Password reset requested for non-existent email: {Email}", Input.Email);
                EmailSent = true;
                return Page();
            }

            // Check if email is verified
            if (!user.EmailConfirmed)
            {
                _logger.LogWarning("Password reset requested for unverified email: {Email}", Input.Email);
                // Still show success to prevent enumeration
                EmailSent = true;
                return Page();
            }

            try
            {
                // Generate password reset token
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                // URL encode the token
                var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                // Build reset link
                var baseUrl = _configuration["AppSettings:BaseUrl"] ?? "https://localhost:7072";
                var resetLink = $"{baseUrl}/ResetPassword?userId={user.Id}&token={encodedToken}";

                // Send password reset email
                await _emailService.SendPasswordResetAsync(
                    user.Email!,
                    user.FirstName ?? "User",
                    resetLink
                );

                _logger.LogInformation("Password reset email sent to {Email}", user.Email);

                // Log audit
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "Password Reset Requested",
                    Timestamp = DateTime.Now,
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                });
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password reset email to {Email}", Input.Email);
                // Still show success to prevent enumeration
            }

            EmailSent = true;
            return Page();
        }
    }
}
