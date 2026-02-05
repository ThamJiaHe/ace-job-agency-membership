using Microsoft.AspNetCore.Identity;

namespace AceJobAgency.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Gender { get; set; }
        public string? NRIC { get; set; }  // Encrypted using IDataProtector
        public DateTime DateOfBirth { get; set; }
        public string? ResumeFilePath { get; set; }
        public string? WhoAmI { get; set; }

        /// <summary>
        /// Tracks when the password was last changed.
        /// Used for minimum and maximum password age enforcement.
        /// </summary>
        public DateTime LastPasswordChange { get; set; } = DateTime.Now;
    }
}
