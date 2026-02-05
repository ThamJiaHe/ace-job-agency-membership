using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Models;
using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Pages
{
    public class IndexModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _context;
        private readonly IDataProtector _protector;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(
            UserManager<ApplicationUser> userManager,
            AuthDbContext context,
            IDataProtectionProvider dataProtectionProvider,
            ILogger<IndexModel> logger)
        {
            _userManager = userManager;
            _context = context;
            // Same purpose string as Register for NRIC encryption/decryption (From Practical 13)
            _protector = dataProtectionProvider.CreateProtector("AceJobAgency.NRIC");
            _logger = logger;
        }

        // Properties bound to the view
        public ApplicationUser? CurrentUser { get; set; }
        public string? DecryptedNRIC { get; set; }
        public string? SessionIpAddress { get; set; }
        public DateTime? LoginTime { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // If not authenticated, just show the hero section
            if (User.Identity?.IsAuthenticated != true)
            {
                return Page();
            }

            // Get current user
            CurrentUser = await _userManager.GetUserAsync(User);
            if (CurrentUser == null)
            {
                // User claim exists but user not found - force logout
                return RedirectToPage("/Logout");
            }

            // Validate session from HttpContext.Session (From Practical 4)
            var sessionId = HttpContext.Session.GetString("SessionId");
            var sessionUserId = HttpContext.Session.GetString("UserId");

            if (string.IsNullOrEmpty(sessionId) || sessionUserId != CurrentUser.Id)
            {
                _logger.LogWarning("Invalid session for user {Email}", CurrentUser.Email);
                return RedirectToPage("/Logout");
            }

            // Verify session exists in database (for multiple login detection)
            var activeSession = await _context.ActiveSessions
                .FirstOrDefaultAsync(s => s.SessionId == sessionId && s.UserId == CurrentUser.Id);

            if (activeSession == null)
            {
                // Session was terminated (multiple login from another device)
                _logger.LogWarning("Session terminated for user {Email} - possible multiple login", CurrentUser.Email);
                HttpContext.Session.Clear();
                return RedirectToPage("/Login", new { expired = true });
            }

            // Get session info for display
            SessionIpAddress = activeSession.IpAddress;
            LoginTime = activeSession.LoginTime;

            // Decrypt NRIC for display (From Practical 13)
            if (!string.IsNullOrEmpty(CurrentUser.NRIC))
            {
                try
                {
                    DecryptedNRIC = _protector.Unprotect(CurrentUser.NRIC);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error decrypting NRIC for user {Email}", CurrentUser.Email);
                    DecryptedNRIC = "Error displaying NRIC";
                }
            }

            return Page();
        }
    }
}
