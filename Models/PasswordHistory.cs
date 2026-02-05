using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AceJobAgency.Models
{
    /// <summary>
    /// Tracks password history to prevent reuse of recent passwords
    /// Assignment Advanced Feature: Avoid password reuse (store 2 previous password hashes)
    /// </summary>
    public class PasswordHistory
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; } = string.Empty;

        [ForeignKey("UserId")]
        public virtual ApplicationUser? User { get; set; }

        /// <summary>
        /// Hashed password (using Identity's password hasher)
        /// </summary>
        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        /// <summary>
        /// When this password was set
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }
}
