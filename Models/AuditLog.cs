namespace AceJobAgency.Models
{
    public class AuditLog
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public string? Action { get; set; }  // "Login Success", "Login Failed", "Logout", "Password Changed"
        public DateTime Timestamp { get; set; }
        public string? IpAddress { get; set; }
    }
}
