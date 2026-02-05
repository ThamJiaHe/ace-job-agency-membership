using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AceJobAgency.Models;

namespace AceJobAgency.Middleware
{
    /// <summary>
    /// Middleware to validate user sessions on every request.
    /// Handles multiple login detection by checking if the session still exists in the database.
    /// From Practical 4 - Session Management
    /// </summary>
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SessionValidationMiddleware> _logger;

        public SessionValidationMiddleware(RequestDelegate next, ILogger<SessionValidationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context, AuthDbContext dbContext,
            SignInManager<ApplicationUser> signInManager)
        {
            // Skip validation for non-authenticated users
            if (context.User.Identity?.IsAuthenticated != true)
            {
                await _next(context);
                return;
            }

            // Skip validation for certain paths (login, logout, static files)
            var path = context.Request.Path.Value?.ToLower() ?? "";
            if (path.Contains("/login") || path.Contains("/logout") ||
                path.Contains("/register") || path.StartsWith("/lib/") ||
                path.StartsWith("/css/") || path.StartsWith("/js/") ||
                path.EndsWith(".css") || path.EndsWith(".js") ||
                path.EndsWith(".ico") || path.EndsWith(".png"))
            {
                await _next(context);
                return;
            }

            // Get session info
            var sessionId = context.Session.GetString("SessionId");
            var sessionUserId = context.Session.GetString("UserId");

            // If no session data, but user is authenticated - invalid state
            if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(sessionUserId))
            {
                _logger.LogWarning("Authenticated user without valid session data");
                await ForceLogoutAsync(context, signInManager, dbContext, sessionUserId, "No Session Data");
                return;
            }

            // From Practical 4: Session Fixation Prevention
            // Validate AuthToken matches between session and cookie
            var sessionAuthToken = context.Session.GetString("AuthToken");
            var cookieAuthToken = context.Request.Cookies["AuthToken"];

            if (string.IsNullOrEmpty(sessionAuthToken) || string.IsNullOrEmpty(cookieAuthToken) ||
                sessionAuthToken != cookieAuthToken)
            {
                _logger.LogWarning("AuthToken mismatch detected - possible session fixation attack");
                await ForceLogoutAsync(context, signInManager, dbContext, sessionUserId, "Session Fixation Detected");
                return;
            }

            // Check if session exists in database (multiple login detection)
            var sessionExists = await dbContext.ActiveSessions
                .AnyAsync(s => s.SessionId == sessionId && s.UserId == sessionUserId);

            if (!sessionExists)
            {
                // Session was terminated (logged in from another device)
                _logger.LogWarning("Session {SessionId} no longer exists - forcing logout", sessionId);
                await ForceLogoutAsync(context, signInManager, dbContext, sessionUserId, "Multiple Login Detected");
                return;
            }

            await _next(context);
        }

        private async Task ForceLogoutAsync(HttpContext context, SignInManager<ApplicationUser> signInManager,
            AuthDbContext dbContext, string? userId, string reason)
        {
            // Log the security event
            if (!string.IsNullOrEmpty(userId))
            {
                dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = userId,
                    Action = $"Session Terminated - {reason}",
                    Timestamp = DateTime.UtcNow,
                    IpAddress = context.Connection.RemoteIpAddress?.ToString()
                });
                await dbContext.SaveChangesAsync();
            }

            // Clear session
            context.Session.Clear();

            // Clear the AuthToken cookie
            context.Response.Cookies.Delete("AuthToken");

            // Sign out the user
            await signInManager.SignOutAsync();

            // Redirect to login with session expired message
            context.Response.Redirect("/Login?expired=true");
        }
    }

    // Extension method to easily add middleware in Program.cs
    public static class SessionValidationMiddlewareExtensions
    {
        public static IApplicationBuilder UseSessionValidation(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<SessionValidationMiddleware>();
        }
    }
}
