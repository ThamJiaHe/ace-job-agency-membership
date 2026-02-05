using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AceJobAgency.Models;
using AceJobAgency.Middleware;
using AceJobAgency.Services;
using Resend;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Resend Email Service Configuration
builder.Services.AddOptions();
builder.Services.AddHttpClient<ResendClient>();
builder.Services.Configure<ResendClientOptions>(options =>
{
    options.ApiToken = builder.Configuration["Resend:ApiKey"]!;
});
builder.Services.AddTransient<IResend, ResendClient>();

// From Practical 5 - EF Core DbContext
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString")));

// From Practical 5 & 13 - Identity with custom ApplicationUser
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password policy - 12 chars minimum (Assignment requirement)
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;

    // Lockout settings - 3 failed attempts (Assignment requirement)
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();

// From Practical 13 - Data Protection for NRIC encryption
builder.Services.AddDataProtection();

// From Practical 4 - Session configuration
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Configure cookie settings for authentication
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";
    options.LogoutPath = "/Logout";
    options.AccessDeniedPath = "/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
});

// Email service for password reset and verification (uses IResend from above)
builder.Services.AddScoped<IEmailService, EmailService>();

// Google reCAPTCHA v3 service
builder.Services.AddHttpClient<IRecaptchaService, RecaptchaService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Middleware order matters! Session before Authentication
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

// Custom middleware for session validation (multiple login detection)
app.UseSessionValidation();

app.MapRazorPages();

app.Run();
