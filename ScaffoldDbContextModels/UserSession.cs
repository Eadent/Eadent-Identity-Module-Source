using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class UserSession
    {
        public long UserSessionId { get; set; }
        public string UserSessionToken { get; set; }
        public short UserSessionExpirationMinutes { get; set; }
        public string EmailAddress { get; set; }
        public string IpAddress { get; set; }
        public short SignInStatusId { get; set; }
        public long? UserId { get; set; }
        public DateTime CreatedDateTimeUtc { get; set; }
        public DateTime LastAccessedDateTimeUtc { get; set; }

        public virtual SignInStatus SignInStatus { get; set; }
        public virtual User User { get; set; }
    }
}
