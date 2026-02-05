using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Models;
using QRCoder;

namespace AceJobAgency.Pages
{
    [Authorize]
    public class EnableTwoFactorModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<EnableTwoFactorModel> _logger;
        private readonly UrlEncoder _urlEncoder;

        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        public EnableTwoFactorModel(
            UserManager<ApplicationUser> userManager,
            ILogger<EnableTwoFactorModel> logger,
            UrlEncoder urlEncoder)
        {
            _userManager = userManager;
            _logger = logger;
            _urlEncoder = urlEncoder;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public string? SharedKey { get; set; }
        public string? AuthenticatorUri { get; set; }
        public string? QrCodeBase64 { get; set; }
        public bool Is2FAEnabled { get; set; }
        public string[]? RecoveryCodes { get; set; }
        public bool ShowRecoveryCodes { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Verification code is required")]
            [StringLength(6, MinimumLength = 6, ErrorMessage = "Code must be 6 digits")]
            [RegularExpression(@"^\d{6}$", ErrorMessage = "Code must be 6 digits")]
            [Display(Name = "Verification Code")]
            public string Code { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            // Check if 2FA is already enabled
            Is2FAEnabled = await _userManager.GetTwoFactorEnabledAsync(user);

            if (!Is2FAEnabled)
            {
                await LoadSharedKeyAndQrCodeUriAsync(user);
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            if (!ModelState.IsValid)
            {
                await LoadSharedKeyAndQrCodeUriAsync(user);
                return Page();
            }

            // Strip spaces and hyphens from the code
            var verificationCode = Input.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

            // Verify the code from the authenticator app
            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!is2faTokenValid)
            {
                ModelState.AddModelError("Input.Code", "Verification code is invalid. Please try again.");
                await LoadSharedKeyAndQrCodeUriAsync(user);
                return Page();
            }

            // Enable 2FA for the user
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            _logger.LogInformation("User {Email} enabled 2FA with authenticator app", user.Email);

            // Generate recovery codes
            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            RecoveryCodes = recoveryCodes?.ToArray();
            ShowRecoveryCodes = true;
            Is2FAEnabled = true;

            _logger.LogInformation("User {Email} generated new recovery codes", user.Email);

            return Page();
        }

        private async Task LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user)
        {
            // Load the authenticator key or generate a new one
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            SharedKey = FormatKey(unformattedKey!);
            AuthenticatorUri = GenerateQrCodeUri(user.Email!, unformattedKey!);

            // Generate QR code as base64 image
            QrCodeBase64 = GenerateQrCodeBase64(AuthenticatorUri);
        }

        private static string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
            int currentPosition = 0;

            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
                currentPosition += 4;
            }

            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.AsSpan(currentPosition));
            }

            return result.ToString().ToLowerInvariant();
        }

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                _urlEncoder.Encode("AceJobAgency"),
                _urlEncoder.Encode(email),
                unformattedKey);
        }

        private static string GenerateQrCodeBase64(string uri)
        {
            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            var qrCodeBytes = qrCode.GetGraphic(20);
            return Convert.ToBase64String(qrCodeBytes);
        }
    }
}
