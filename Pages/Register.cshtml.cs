using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IDataProtector _protector;
        private readonly IWebHostEnvironment _environment;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        private readonly IRecaptchaService _recaptchaService;
        private readonly AuthDbContext _context;

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IDataProtectionProvider dataProtectionProvider,
            IWebHostEnvironment environment,
            ILogger<RegisterModel> logger,
            IEmailService emailService,
            IConfiguration configuration,
            IRecaptchaService recaptchaService,
            AuthDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            // From Practical 13 - Create protector with purpose string
            _protector = dataProtectionProvider.CreateProtector("AceJobAgency.NRIC");
            _environment = environment;
            _logger = logger;
            _emailService = emailService;
            _configuration = configuration;
            _recaptchaService = recaptchaService;
            _context = context;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        [BindProperty]
        public string? RecaptchaToken { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "First name is required")]
            [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
            [RegularExpression(@"^[a-zA-Z\s]+$", ErrorMessage = "First name can only contain letters")]
            [Display(Name = "First Name")]
            public string FirstName { get; set; } = string.Empty;

            [Required(ErrorMessage = "Last name is required")]
            [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
            [RegularExpression(@"^[a-zA-Z\s]+$", ErrorMessage = "Last name can only contain letters")]
            [Display(Name = "Last Name")]
            public string LastName { get; set; } = string.Empty;

            [Required(ErrorMessage = "Gender is required")]
            public string Gender { get; set; } = "Male";

            [Required(ErrorMessage = "NRIC is required")]
            [StringLength(9, MinimumLength = 9, ErrorMessage = "NRIC must be exactly 9 characters")]
            [RegularExpression(@"^[STFGM]\d{7}[A-Z]$", ErrorMessage = "Invalid NRIC format (e.g., S1234567A)")]
            [Display(Name = "NRIC")]
            public string NRIC { get; set; } = string.Empty;

            [Required(ErrorMessage = "Email is required")]
            [EmailAddress(ErrorMessage = "Invalid email address")]
            [Display(Name = "Email")]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "Password is required")]
            [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters")]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; } = string.Empty;

            [Required(ErrorMessage = "Please confirm your password")]
            [DataType(DataType.Password)]
            [Compare("Password", ErrorMessage = "Passwords do not match")]
            [Display(Name = "Confirm Password")]
            public string ConfirmPassword { get; set; } = string.Empty;

            [Required(ErrorMessage = "Date of birth is required")]
            [DataType(DataType.Date)]
            [Display(Name = "Date of Birth")]
            public DateTime DateOfBirth { get; set; }

            [Display(Name = "Resume")]
            public IFormFile? Resume { get; set; }

            [StringLength(500, ErrorMessage = "Who Am I cannot exceed 500 characters")]
            [Display(Name = "Who Am I")]
            public string? WhoAmI { get; set; }
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Verify reCAPTCHA v3 token
            var recaptchaResult = await _recaptchaService.VerifyAsync(RecaptchaToken ?? "", "register");
            if (!recaptchaResult.Success)
            {
                _logger.LogWarning("reCAPTCHA verification failed for registration attempt. Score: {Score}", recaptchaResult.Score);

                // Log failed reCAPTCHA attempt to audit log
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = null, // No user yet
                    Action = $"Registration Failed - reCAPTCHA: {recaptchaResult.ErrorMessage}",
                    Timestamp = DateTime.Now,
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                });
                await _context.SaveChangesAsync();

                ModelState.AddModelError(string.Empty, recaptchaResult.ErrorMessage ?? "Security verification failed. Please try again.");
                return Page();
            }

            _logger.LogInformation("reCAPTCHA passed for registration. Score: {Score}", recaptchaResult.Score);

            // Server-side password complexity validation (From Practical 2)
            if (!ValidatePasswordComplexity(Input.Password))
            {
                ModelState.AddModelError("Input.Password",
                    "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*)");
                return Page();
            }

            // Check if email already exists
            var existingUser = await _userManager.FindByEmailAsync(Input.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Input.Email",
                    "This email is already registered. Try logging in instead.");
                return Page();
            }

            // Validate date of birth - must be in the past
            if (Input.DateOfBirth.Date >= DateTime.Today)
            {
                ModelState.AddModelError("Input.DateOfBirth",
                    "Date of birth must be in the past.");
                return Page();
            }

            // Validate age (must be between 16 and 100)
            var age = DateTime.Today.Year - Input.DateOfBirth.Year;
            if (Input.DateOfBirth.Date > DateTime.Today.AddYears(-age)) age--;
            if (age < 16)
            {
                ModelState.AddModelError("Input.DateOfBirth",
                    "You must be at least 16 years old to register.");
                return Page();
            }
            if (age > 100)
            {
                ModelState.AddModelError("Input.DateOfBirth",
                    "Please enter a valid date of birth.");
                return Page();
            }

            // Handle resume file upload
            string? resumeFilePath = null;
            if (Input.Resume != null && Input.Resume.Length > 0)
            {
                var uploadResult = await HandleResumeUpload(Input.Resume);
                if (!uploadResult.Success)
                {
                    ModelState.AddModelError("Input.Resume", uploadResult.ErrorMessage!);
                    return Page();
                }
                resumeFilePath = uploadResult.FilePath;
            }

            // Encrypt NRIC using IDataProtector (From Practical 13)
            string encryptedNRIC = _protector.Protect(Input.NRIC);

            // Create the user
            var user = new ApplicationUser
            {
                UserName = Input.Email,
                Email = Input.Email,
                FirstName = SanitizeInput(Input.FirstName),
                LastName = SanitizeInput(Input.LastName),
                Gender = Input.Gender,
                NRIC = encryptedNRIC,  // Encrypted!
                DateOfBirth = Input.DateOfBirth,
                ResumeFilePath = resumeFilePath,
                WhoAmI = SanitizeInput(Input.WhoAmI),
                EmailConfirmed = false,  // Require email verification
                LastPasswordChange = DateTime.Now  // Set initial password change timestamp
            };

            var result = await _userManager.CreateAsync(user, Input.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} registered successfully.", Input.Email);

                // Save initial password to history (for password reuse prevention)
                var freshUser = await _userManager.FindByIdAsync(user.Id);
                if (freshUser?.PasswordHash != null)
                {
                    _context.PasswordHistories.Add(new PasswordHistory
                    {
                        UserId = user.Id,
                        PasswordHash = freshUser.PasswordHash,
                        CreatedAt = DateTime.Now
                    });
                    await _context.SaveChangesAsync();
                }

                // Generate email verification token
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                // URL encode the token for safe transmission
                var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                // Build verification link
                var baseUrl = _configuration["AppSettings:BaseUrl"] ?? "https://localhost:7072";
                var verificationLink = $"{baseUrl}/VerifyEmail?userId={user.Id}&token={encodedToken}";

                // Send verification email
                try
                {
                    await _emailService.SendEmailVerificationAsync(
                        user.Email!,
                        user.FirstName ?? "User",
                        verificationLink
                    );
                    _logger.LogInformation("Verification email sent to {Email}", user.Email);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send verification email to {Email}", user.Email);
                    // Don't fail registration if email fails - user can request resend
                }

                // Redirect to login with success message
                TempData["SuccessMessage"] = "Registration successful! Please check your email to verify your account before logging in.";
                return RedirectToPage("/Login");
            }

            // Add Identity errors to ModelState
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }

        /// <summary>
        /// Server-side password complexity validation (From Practical 2)
        /// Score-based system: must achieve score of 5
        /// </summary>
        private bool ValidatePasswordComplexity(string password)
        {
            if (string.IsNullOrEmpty(password) || password.Length < 12)
                return false;

            int score = 0;

            // Check for lowercase
            if (Regex.IsMatch(password, @"[a-z]"))
                score++;

            // Check for uppercase
            if (Regex.IsMatch(password, @"[A-Z]"))
                score++;

            // Check for digits
            if (Regex.IsMatch(password, @"\d"))
                score++;

            // Check for special characters
            if (Regex.IsMatch(password, @"[!@#$%^&*]"))
                score++;

            // Check for minimum length
            if (password.Length >= 12)
                score++;

            // Must meet all 5 requirements
            return score >= 5;
        }

        /// <summary>
        /// Handle resume file upload with security validations
        /// </summary>
        private async Task<(bool Success, string? FilePath, string? ErrorMessage)> HandleResumeUpload(IFormFile file)
        {
            // Validate file size (max 5MB)
            const int maxFileSize = 5 * 1024 * 1024;
            if (file.Length > maxFileSize)
            {
                return (false, null, "File size must be less than 5MB.");
            }

            // Validate file extension
            var allowedExtensions = new[] { ".pdf", ".docx" };
            var fileExtension = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (!allowedExtensions.Contains(fileExtension))
            {
                return (false, null, "Only PDF and DOCX files are allowed.");
            }

            // Validate content type (additional security check)
            var allowedContentTypes = new[]
            {
                "application/pdf",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            };
            if (!allowedContentTypes.Contains(file.ContentType.ToLowerInvariant()))
            {
                return (false, null, "Invalid file type.");
            }

            // Create uploads directory if it doesn't exist
            var uploadsFolder = Path.Combine(_environment.ContentRootPath, "Uploads", "Resumes");
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            // Generate secure filename with GUID (never use client filename)
            var secureFileName = $"{Guid.NewGuid()}{fileExtension}";
            var filePath = Path.Combine(uploadsFolder, secureFileName);

            // Save file
            try
            {
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                // Return relative path for storage in database
                return (true, $"Uploads/Resumes/{secureFileName}", null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading resume file");
                return (false, null, "An error occurred while uploading the file.");
            }
        }

        /// <summary>
        /// Sanitize user input - trim whitespace
        /// From Practical 3: XSS Prevention
        /// Note: We store data as-is and rely on Razor's automatic HTML encoding
        /// when displaying. This allows users to input special characters while
        /// preventing XSS attacks at render time.
        /// </summary>
        private string? SanitizeInput(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // Trim whitespace, but allow special characters
            // Razor will automatically HTML-encode when displaying with @Model.Property
            return input.Trim();
        }
    }
}
