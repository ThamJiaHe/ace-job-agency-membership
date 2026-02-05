using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Models;

namespace AceJobAgency.Pages
{
    [Authorize]
    public class DisableTwoFactorModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<DisableTwoFactorModel> _logger;

        public DisableTwoFactorModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<DisableTwoFactorModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public bool Is2FAEnabled { get; set; }
        public bool DisableSuccess { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Password is required to disable 2FA")]
            [DataType(DataType.Password)]
            [Display(Name = "Current Password")]
            public string Password { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            Is2FAEnabled = await _userManager.GetTwoFactorEnabledAsync(user);

            if (!Is2FAEnabled)
            {
                return RedirectToPage("/EnableTwoFactor");
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
                Is2FAEnabled = true;
                return Page();
            }

            // Verify password before allowing 2FA disable
            var passwordValid = await _userManager.CheckPasswordAsync(user, Input.Password);
            if (!passwordValid)
            {
                ModelState.AddModelError("Input.Password", "Incorrect password.");
                Is2FAEnabled = true;
                return Page();
            }

            // Disable 2FA
            var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Failed to disable 2FA. Please try again.");
                Is2FAEnabled = true;
                return Page();
            }

            // Reset authenticator key
            await _userManager.ResetAuthenticatorKeyAsync(user);

            _logger.LogInformation("User {Email} disabled 2FA", user.Email);

            // Refresh sign-in
            await _signInManager.RefreshSignInAsync(user);

            DisableSuccess = true;
            Is2FAEnabled = false;

            return Page();
        }
    }
}
