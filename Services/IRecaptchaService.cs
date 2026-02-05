namespace AceJobAgency.Services
{
    /// <summary>
    /// Service interface for Google reCAPTCHA v3 verification
    /// reCAPTCHA v3 returns a score (0.0 - 1.0) instead of a checkbox
    /// Higher scores indicate more likely human interaction
    /// </summary>
    public interface IRecaptchaService
    {
        /// <summary>
        /// Verify a reCAPTCHA token with Google's API
        /// </summary>
        /// <param name="token">The reCAPTCHA token from the client</param>
        /// <param name="expectedAction">The action name to verify (e.g., "login", "register")</param>
        /// <returns>Tuple of (success, score) - score is 0.0-1.0, higher is more human</returns>
        Task<(bool Success, float Score, string? ErrorMessage)> VerifyAsync(string token, string expectedAction);
    }
}
