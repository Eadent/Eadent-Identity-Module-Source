using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class PasswordReset
    {
        public long PasswordResetId { get; set; }
        public string ResetToken { get; set; }
        public DateTime RequestedDateTimeUtc { get; set; }
        public DateTime ExpirationDateTimeUtc { get; set; }
        public string EmailAddress { get; set; }
        public string IpAddress { get; set; }
        public long? UserId { get; set; }

        public virtual User User { get; set; }
    }
}
