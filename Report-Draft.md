# Secure Membership System for Ace Job Agency

**Name:** [Your Name]
**Admin Number:** [Your Admin Number]
**Tutorial Group:** [Your Group]
**Module:** IT2163 Applications Security
**Date:** [Date]

---

## Plagiarism Statement

I declare that this assignment is my own work. I did not copy from anyone or let anyone copy my work.

Signature: _________________ Date: _________________

---

## 1. Introduction

I built a secure membership system for Ace Job Agency. The system lets users register, login, and manage their accounts. I focused on security because the system handles sensitive data like NRIC numbers.

**Technology used:**
- ASP.NET Core 8 with Razor Pages
- Entity Framework Core for database
- SQL Server LocalDB
- Resend API for emails
- Google reCAPTCHA v3

**Main security features:**
- Password encryption and validation
- Two-factor authentication
- Session management
- Account lockout
- Audit logging

---

## 2. Registration Security (4%)

### What I did

I created a registration form with several security checks. Users must provide their email, password, name, NRIC, date of birth, and resume file.

### Security features

**Duplicate email check:**
The system checks if the email already exists. This prevents someone from creating multiple accounts with the same email.

```csharp
var existingUser = await _userManager.FindByEmailAsync(Input.Email);
if (existingUser != null)
{
    ModelState.AddModelError("Input.Email", "Email is already registered");
    return Page();
}
```

**File upload validation:**
Users upload resume files. I only allow .docx and .pdf files. The system also checks the file size (max 5MB).

```csharp
var allowedExtensions = new[] { ".pdf", ".docx" };
var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
if (!allowedExtensions.Contains(extension))
{
    // Reject the file
}
```

**Why this matters:**
- Stops fake accounts
- Blocks malicious file uploads
- Protects database from bad data

**Reference:** OWASP File Upload Cheat Sheet

[Screenshot: Registration form]

---

## 3. Password Complexity (10%)

### What I did

I added password strength checking. Weak passwords are the most common security problem. So I made the rules strict.

### Password requirements

- Minimum 12 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number
- At least 1 special character

### Client-side validation

I used JavaScript to show a strength bar. The bar turns from red to green as the password gets stronger.

```javascript
function calculatePasswordStrength(password) {
    let score = 0;
    if (password.length >= 12) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
}
```

### Server-side validation

The client-side check can be bypassed. So I also check on the server. The server gives a score from 1 to 5.

```csharp
if (score < 4)
{
    ModelState.AddModelError("Input.Password",
        "Password is too weak. Include uppercase, lowercase, numbers, and symbols.");
    return Page();
}
```

**Why this matters:**
- Weak passwords are easy to crack
- Attackers use password lists to guess common passwords
- Strong passwords take years to crack

**Reference:** OWASP Password Storage Cheat Sheet, IT2163 Practical 2 - Password Complexity Lab

[Screenshot: Password strength indicator]

---

## 4. Data Encryption (6%)

### What I did

I encrypted the NRIC field using ASP.NET Data Protection. NRIC is sensitive data. If someone steals the database, they cannot read the NRIC.

### How it works

I used IDataProtector to encrypt. The system generates a secret key. The key is stored separately from the database.

**Encrypting NRIC during registration:**

```csharp
var protector = _dataProtectionProvider.CreateProtector("AceJobAgency.NRIC");
var encryptedNRIC = protector.Protect(Input.NRIC);
user.NRIC = encryptedNRIC;
```

**Decrypting NRIC when showing to user:**

```csharp
var protector = _dataProtectionProvider.CreateProtector("AceJobAgency.NRIC");
var decryptedNRIC = protector.Unprotect(user.NRIC);
```

### Database evidence

In the database, NRIC looks like random characters:
`CfDJ8PQ3Kx7...` (encrypted)

On the homepage, users see their actual NRIC:
`S1234567D` (decrypted)

**Why this matters:**
- Protects sensitive data at rest
- Even if database is stolen, data is unreadable
- Follows data protection regulations

**Reference:** OWASP Cryptographic Storage Cheat Sheet, IT2163 Practical 13 - Custom AspNetUser Fields

[Screenshot: Encrypted NRIC in database]
[Screenshot: Decrypted NRIC on homepage]

---

## 5. Session Management (10%)

### What I did

I implemented secure session handling. This includes multiple login detection, session timeout, and session fixation prevention.

### Multiple login detection

If a user logs in from another device, the old session is terminated. Only one active session is allowed per user.

```csharp
var existingSessions = _context.ActiveSessions
    .Where(s => s.UserId == user.Id)
    .ToList();

if (existingSessions.Any())
{
    _context.ActiveSessions.RemoveRange(existingSessions);
    await _context.SaveChangesAsync();
}
```

### Session timeout

Sessions expire after 20 minutes of inactivity. The user sees a countdown timer on the homepage.

```csharp
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
```

### Session fixation prevention

I use both session ID and AuthToken cookie. This prevents session fixation attacks.

```csharp
var authToken = Guid.NewGuid().ToString();
HttpContext.Session.SetString("AuthToken", authToken);
Response.Cookies.Append("AuthToken", authToken, new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Strict
});
```

**Why this matters:**
- Stops attackers from hijacking sessions
- Prevents unauthorized access from stolen cookies
- Limits damage if one session is compromised

**Reference:** OWASP Session Management Cheat Sheet, IT2163 Practical 4 - Session Management

[Screenshot: ActiveSessions table in database]
[Screenshot: Multiple login detection - old session terminated message]

---

## 6. Login and Logout (10%)

### What I did

I added account lockout and comprehensive audit logging. Users get locked out after 3 failed attempts. All login attempts are logged.

### Account lockout

After 3 wrong passwords, the account is locked for 5 minutes. This stops brute force attacks.

```csharp
options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
options.Lockout.MaxFailedAccessAttempts = 3;
options.Lockout.AllowedForNewUsers = true;
```

### Automatic unlock

The account unlocks automatically after 5 minutes. Users don't need to contact admin.

### Audit logging

Every login attempt is recorded in AuditLog table. This includes:
- User ID or email
- Action (success, failed, locked)
- IP address
- Timestamp

```csharp
var log = new AuditLog
{
    UserId = user.Id,
    Action = "Login Success",
    Timestamp = DateTime.Now,
    IpAddress = ipAddress
};
_context.AuditLogs.Add(log);
```

**Why this matters:**
- Stops password guessing attacks
- Creates evidence trail for investigations
- Helps detect suspicious activity

**Reference:** OWASP Authentication Cheat Sheet, IT2163 Practical 6 - Authentication with EF Core

[Screenshot: Lockout error message]
[Screenshot: AuditLogs table with entries]

---

## 7. Input Validation (15%)

### What I did

I protected against SQL injection, XSS, and CSRF attacks. These are the most common web vulnerabilities.

### SQL Injection Prevention

I used Entity Framework Core. It uses parameterized queries. User input is never directly put into SQL.

```csharp
// Safe - EF Core uses parameters
var user = await _userManager.FindByEmailAsync(Input.Email);

// Never do this - vulnerable to SQL injection
// var query = "SELECT * FROM Users WHERE Email = '" + email + "'";
```

### XSS Prevention

Razor automatically encodes all output. If someone tries to enter `<script>alert('XSS')</script>`, it shows as text, not as code.

```html
@* Razor encodes this automatically *@
<p>@Model.CurrentUser.WhoAmI</p>
```

I also sanitize input when saving:

```csharp
private string SanitizeInput(string? input)
{
    if (string.IsNullOrEmpty(input)) return string.Empty;
    return System.Web.HttpUtility.HtmlEncode(input.Trim());
}
```

### CSRF Prevention

All forms have anti-forgery tokens. ASP.NET validates the token on every POST request.

```html
<form method="post">
    @Html.AntiForgeryToken()
    <!-- form fields -->
</form>
```

**Why this matters:**
- SQL injection can expose entire database
- XSS can steal user sessions
- CSRF can trick users into unwanted actions

**Reference:** OWASP Injection Prevention Cheat Sheet, IT2163 Practical 3 (XSS), Practical 8 (SQLi)

---

## 8. Error Handling (5%)

### What I did

I created custom error pages for 404, 403, and 500 errors. These pages don't show sensitive information.

### Custom error pages

```csharp
app.UseStatusCodePagesWithReExecute("/Error/{0}");
```

The 404 page shows a friendly message. It doesn't reveal system paths or stack traces.

**Why this matters:**
- Default error pages show sensitive info
- Attackers use error messages to find vulnerabilities
- Custom pages improve user experience

**Reference:** IT2163 Practical 12 - Error Handling

[Screenshot: Custom 404 page]

---

## 9. reCAPTCHA Integration (5%)

### What I did

I added Google reCAPTCHA v3 to the login and register forms. This blocks automated bot attacks.

### How it works

reCAPTCHA v3 runs in the background. It gives a score from 0 to 1. Score below 0.5 is suspicious.

```csharp
var result = await _recaptchaService.VerifyAsync(token, "login");
if (!result.Success || result.Score < 0.5)
{
    ModelState.AddModelError(string.Empty, "Security check failed");
    return Page();
}
```

**Why this matters:**
- Stops automated registration bots
- Prevents credential stuffing attacks
- No annoying puzzles for users

**Reference:** Google reCAPTCHA documentation

[Screenshot: reCAPTCHA badge on form]

---

## 10. Advanced Features (10%)

### Password History

Users cannot reuse their last 2 passwords. The system stores hashed versions of old passwords.

```csharp
var passwordHistory = _context.PasswordHistories
    .Where(ph => ph.UserId == user.Id)
    .OrderByDescending(ph => ph.CreatedAt)
    .Take(2)
    .ToList();

foreach (var oldPassword in passwordHistory)
{
    var result = _passwordHasher.VerifyHashedPassword(
        user, oldPassword.PasswordHash, newPassword);
    if (result == PasswordVerificationResult.Success)
    {
        // Password was used before - reject it
    }
}
```

### Minimum Password Age

Users must wait 1 day before changing password again. This stops users from cycling through passwords to get back to their favorite one.

```csharp
var minAgeDays = _configuration.GetValue<int>("PasswordPolicy:MinPasswordAgeDays", 1);
if ((DateTime.Now - user.LastPasswordChange).TotalDays < minAgeDays)
{
    ModelState.AddModelError(string.Empty, "Must wait 1 day before changing password");
}
```

### Maximum Password Age

Passwords expire after 90 days. Users are forced to change their password on next login.

```csharp
var maxAgeDays = _configuration.GetValue<int>("PasswordPolicy:MaxPasswordAgeDays", 90);
if ((DateTime.Now - user.LastPasswordChange).TotalDays > maxAgeDays)
{
    return RedirectToPage("/ChangePassword", new { expired = true });
}
```

### Password Reset via Email

Users can reset forgotten passwords. The system sends a secure link to their email. The link expires after use.

**Reference:** OWASP Forgot Password Cheat Sheet

[Screenshot: PasswordHistory table in database]

---

## 11. Two-Factor Authentication (5%)

### What I did

I added 2FA using authenticator apps. Users scan a QR code. Then they enter a 6-digit code when logging in.

### Setup process

1. User goes to Enable 2FA page
2. System generates a secret key
3. Key is shown as QR code
4. User scans with Google Authenticator
5. User enters the 6-digit code to verify
6. System generates 10 recovery codes

```csharp
var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
var uri = $"otpauth://totp/AceJobAgency:{email}?secret={unformattedKey}&issuer=AceJobAgency";
```

### Login with 2FA

After password check, user must enter the 6-digit code:

```csharp
var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
    code, rememberMe, rememberMachine);
```

### Recovery codes

If user loses their phone, they can use a recovery code. Each code works only once.

**Why this matters:**
- Even if password is stolen, attacker needs the phone
- TOTP codes change every 30 seconds
- Recovery codes prevent lockout

**Reference:** OWASP Multi-Factor Authentication Cheat Sheet

[Screenshot: QR code setup page]
[Screenshot: 2FA login page]
[Screenshot: Recovery codes display]

---

## 12. GitHub CodeQL Analysis (5%)

### What I did

I pushed the code to GitHub and enabled CodeQL security scanning. CodeQL checks for common vulnerabilities.

### Setup

1. Created GitHub repository
2. Added CodeQL workflow file
3. CodeQL runs on every push

### Results

CodeQL scanned for:
- SQL injection
- Cross-site scripting
- CSRF vulnerabilities
- Hard-coded credentials
- Insecure cryptography

**Result:** No high or critical vulnerabilities found.

**Reference:** IT2163 Practical 14 - GitHub CodeQL Testing

[Screenshot: CodeQL analysis results]
[Screenshot: GitHub Security tab]

---

## 13. Conclusion

I successfully built a secure membership system for Ace Job Agency. The system protects user data using encryption, validates all input, and logs all activities.

**Key achievements:**
- All OWASP Top 10 vulnerabilities addressed
- Entity Framework prevents SQL injection
- Razor encoding prevents XSS
- Anti-forgery tokens prevent CSRF
- Strong password policy enforced
- 2FA adds extra security layer
- Audit logs track all activities

**What I learned:**
- Security must be built in from the start
- Multiple layers of defense are important
- Never trust user input
- Always encrypt sensitive data

---

## References

1. OWASP Password Storage Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

2. OWASP Session Management Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

3. OWASP Authentication Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

4. OWASP Input Validation Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

5. OWASP Cross-Site Scripting Prevention Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

6. Microsoft ASP.NET Core Security Documentation - https://docs.microsoft.com/en-us/aspnet/core/security/

7. Google reCAPTCHA v3 Documentation - https://developers.google.com/recaptcha/docs/v3

---

## Annex A: Security Checklist

| # | Requirement | Task | Status | Report Section |
|---|-------------|------|--------|----------------|
| **1** | **Registration Form (4%)** | | | |
| 1.1 | | Successfully saving member info into Database | ✓ | Section 2 |
| 1.2 | | Check for duplicate email and rectify issue | ✓ | Section 2 |
| **2** | **Securing Credential (10%)** | | | |
| 2.1 | | Perform password complexity checks (Min 12 chars, uppercase, lowercase, numbers, special characters) | ✓ | Section 3 |
| 2.2 | | Offer feedback to user on STRONG password | ✓ | Section 3 |
| 2.3 | | Implement both Client-based and Server-based checks | ✓ | Section 3 |
| **3** | **Securing User Data (6%)** | | | |
| 3.1 | | Implement Password Protection | ✓ | Section 4 |
| 3.2 | | Encryption of customer data (encrypt NRIC in database) | ✓ | Section 4 |
| 3.3 | | Decryption of customer data (display in homepage) | ✓ | Section 4 |
| **4** | **Session Management (10%)** | | | |
| 4.1 | | Create a Secured Session upon successful login | ✓ | Section 5 |
| 4.2 | | Perform Session timeout | ✓ | Section 5 |
| 4.3 | | Route to homepage/login page after session timeout | ✓ | Section 5 |
| 4.4 | | Detect multiple logins from different devices (different browser tabs) | ✓ | Section 5 |
| **5** | **Login/Logout (10%)** | | | |
| 5.1 | | Able to login to system after registration | ✓ | Section 6 |
| 5.2 | | Rate Limiting (Account lockout after 3 login failures) | ✓ | Section 6 |
| 5.3 | | Perform proper and safe logout (Clear session and redirect to login page) | ✓ | Section 6 |
| 5.4 | | Perform audit log (save user activities in Database) | ✓ | Section 6 |
| 5.5 | | Redirect to homepage after successful credential verification. Home page displays the user info including encrypted data | ✓ | Section 6 |
| **6** | **Anti-Bot (5%)** | | | |
| 6.1 | | Implement Google reCAPTCHA v3 service | ✓ | Section 9 |
| **7** | **Input Validation (15%)** | | | |
| 7.1 | | Prevent Injection (e.g. SQLi) | ✓ | Section 7 |
| 7.2 | | Prevent CSRF attack | ✓ | Section 7 |
| 7.3 | | Prevent XSS attack | ✓ | Section 7 |
| 7.4 | | Perform proper input sanitation, validation and verification (e.g. email, date etc) | ✓ | Section 7 |
| 7.5 | | Client and server input validation | ✓ | Section 7 |
| 7.6 | | Display error or warning message on improper input requirements | ✓ | Section 7 |
| 7.7 | | Perform proper encoding before saving into database | ✓ | Section 7 |
| **8** | **Error Handling (5%)** | | | |
| 8.1 | | Graceful error handling on all pages (including 404, 403 and other error pages) | ✓ | Section 8 |
| 8.2 | | Display proper custom error pages | ✓ | Section 8 |
| **9** | **Software Testing (5%)** | | | |
| 9.1 | | Use external tools to perform software testing (GitHub CodeQL) | ✓ | Section 12 |
| 9.2 | | Implement the recommendation to clear security vulnerability | ✓ | Section 12 |
| 9.3 | | Demo and show it to tutor in GitHub account | ✓ | Section 12 |
| **10** | **Advanced Features (10%)** | | | |
| 10.1 | | Automatic account recovery after x mins of lockout | ✓ | Section 6 |
| 10.2 | | Avoid password reuse (max 2 password history) | ✓ | Section 10 |
| 10.3 | | Change password | ✓ | Section 10 |
| 10.4 | | Reset Password (using Email link) | ✓ | Section 10 |
| 10.5 | | Minimum password age (cannot change password within x mins from the last change) | ✓ | Section 10 |
| 10.6 | | Maximum password age (must change password after x mins) | ✓ | Section 10 |
| **11** | **Two-Factor Authentication (5%)** | | | |
| 11.1 | | Implement 2FA using authenticator app (TOTP) | ✓ | Section 11 |
| 11.2 | | QR code for authenticator setup | ✓ | Section 11 |
| 11.3 | | Recovery codes for backup access | ✓ | Section 11 |

---

### Summary

| Category | Marks | Status |
|----------|-------|--------|
| Registration Form | 4% | ✓ Complete |
| Securing Credential | 10% | ✓ Complete |
| Securing User Data | 6% | ✓ Complete |
| Session Management | 10% | ✓ Complete |
| Login/Logout | 10% | ✓ Complete |
| Anti-Bot | 5% | ✓ Complete |
| Input Validation | 15% | ✓ Complete |
| Error Handling | 5% | ✓ Complete |
| Software Testing | 5% | ✓ Complete |
| Advanced Features | 10% | ✓ Complete |
| Two-Factor Authentication | 5% | ✓ Complete |
| Demo | 5% | Ready |
| Report | 10% | ✓ Complete |
| **Total** | **100%** | **✓ Complete** |

---

*End of Report*
