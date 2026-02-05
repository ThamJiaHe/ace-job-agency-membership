using System.Text.Json;

namespace AceJobAgency.Services
{
    /// <summary>
    /// Google reCAPTCHA v3 verification service
    /// Calls Google's siteverify API to validate tokens and get scores
    /// </summary>
    public class RecaptchaService : IRecaptchaService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private readonly ILogger<RecaptchaService> _logger;
        private readonly string _secretKey;
        private const string VerifyUrl = "https://www.google.com/recaptcha/api/siteverify";
        private const float MinimumScore = 0.5f; // Reject if score below this

        public RecaptchaService(
            HttpClient httpClient,
            IConfiguration configuration,
            ILogger<RecaptchaService> logger)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _logger = logger;
            _secretKey = _configuration["Recaptcha:SecretKey"] ?? "";
        }

        public async Task<(bool Success, float Score, string? ErrorMessage)> VerifyAsync(string token, string expectedAction)
        {
            // If reCAPTCHA is not configured, skip verification (for development)
            if (string.IsNullOrEmpty(_secretKey) || _secretKey == "YOUR_SECRET_KEY_HERE")
            {
                _logger.LogWarning("reCAPTCHA secret key not configured - skipping verification");
                return (true, 1.0f, null);
            }

            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("reCAPTCHA token is empty");
                return (false, 0f, "reCAPTCHA verification failed. Please try again.");
            }

            try
            {
                // Prepare the verification request
                var content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "secret", _secretKey },
                    { "response", token }
                });

                // Call Google's verification API
                var response = await _httpClient.PostAsync(VerifyUrl, content);
                var jsonResponse = await response.Content.ReadAsStringAsync();

                _logger.LogDebug("reCAPTCHA API response: {Response}", jsonResponse);

                // Parse the response
                var result = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (result == null)
                {
                    _logger.LogError("Failed to parse reCAPTCHA response");
                    return (false, 0f, "reCAPTCHA verification failed. Please try again.");
                }

                // Check if verification was successful
                if (!result.Success)
                {
                    var errors = result.ErrorCodes != null ? string.Join(", ", result.ErrorCodes) : "Unknown";
                    _logger.LogWarning("reCAPTCHA verification failed. Errors: {Errors}", errors);
                    return (false, 0f, "reCAPTCHA verification failed. Please try again.");
                }

                // Verify the action matches what we expected
                if (!string.IsNullOrEmpty(expectedAction) && result.Action != expectedAction)
                {
                    _logger.LogWarning("reCAPTCHA action mismatch. Expected: {Expected}, Got: {Actual}",
                        expectedAction, result.Action);
                    return (false, result.Score, "reCAPTCHA verification failed. Invalid action.");
                }

                // Check if the score meets our minimum threshold
                if (result.Score < MinimumScore)
                {
                    _logger.LogWarning("reCAPTCHA score too low: {Score}", result.Score);
                    return (false, result.Score, "Suspicious activity detected. Please try again.");
                }

                _logger.LogInformation("reCAPTCHA verified successfully. Score: {Score}, Action: {Action}",
                    result.Score, result.Action);

                return (true, result.Score, null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying reCAPTCHA token");
                return (false, 0f, "reCAPTCHA verification error. Please try again.");
            }
        }

        /// <summary>
        /// Response model for Google reCAPTCHA v3 API
        /// </summary>
        private class RecaptchaResponse
        {
            public bool Success { get; set; }
            public float Score { get; set; }
            public string? Action { get; set; }
            public DateTime ChallengeTs { get; set; }
            public string? Hostname { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("error-codes")]
            public string[]? ErrorCodes { get; set; }
        }
    }
}
