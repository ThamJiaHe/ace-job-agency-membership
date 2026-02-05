namespace AceJobAgency.Models
{
    public class ActiveSession
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public string? SessionId { get; set; }
        public DateTime LoginTime { get; set; }
        public string? IpAddress { get; set; }
    }
}
