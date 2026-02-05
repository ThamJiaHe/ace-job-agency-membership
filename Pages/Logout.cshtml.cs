using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Models;

namespace AceJobAgency.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _context;
        private readonly ILogger<LogoutModel> _logger;

        public LogoutModel(
            SignInManager<ApplicationUser> signInManager,
            AuthDbContext context,
            ILogger<LogoutModel> logger)
        {
            _signInManager = signInManager;
            _context = context;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // Perform logout when page is accessed
            await PerformLogout();
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            await PerformLogout();
            return Page();
        }

        private async Task PerformLogout()
        {
            var userId = HttpContext.Session.GetString("UserId");
            var sessionId = HttpContext.Session.GetString("SessionId");
            var ipAddress = GetClientIpAddress();

            // Remove session from ActiveSessions table
            if (!string.IsNullOrEmpty(sessionId))
            {
                var session = _context.ActiveSessions
                    .FirstOrDefault(s => s.SessionId == sessionId);

                if (session != null)
                {
                    _context.ActiveSessions.Remove(session);
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Session {SessionId} removed from database", sessionId);
                }
            }

            // Log audit
            if (!string.IsNullOrEmpty(userId))
            {
                await LogAuditAsync(userId, "Logout", ipAddress);
            }

            // Clear HttpContext session
            HttpContext.Session.Clear();

            // Clear the AuthToken cookie (From Practical 4 - Session Fixation Prevention)
            Response.Cookies.Delete("AuthToken");

            // Sign out from Identity
            await _signInManager.SignOutAsync();

            _logger.LogInformation("User {UserId} logged out successfully", userId ?? "Unknown");
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
