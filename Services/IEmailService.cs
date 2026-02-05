namespace AceJobAgency.Services
{
    /// <summary>
    /// Interface for email service operations
    /// Used for password reset and email verification
    /// </summary>
    public interface IEmailService
    {
        /// <summary>
        /// Send email verification link to new user
        /// </summary>
        Task SendEmailVerificationAsync(string toEmail, string userName, string verificationLink);

        /// <summary>
        /// Send password reset link to user
        /// </summary>
        Task SendPasswordResetAsync(string toEmail, string userName, string resetLink);

        /// <summary>
        /// Send notification when password is changed
        /// </summary>
        Task SendPasswordChangedNotificationAsync(string toEmail, string userName);
    }
}
